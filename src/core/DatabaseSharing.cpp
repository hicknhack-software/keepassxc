/*
 *  Copyright (C) 2018 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "DatabaseSharing.h"

#include "core/Clock.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/DatabaseIcons.h"
#include "core/Entry.h"
#include "core/FilePath.h"
#include "core/Group.h"
#include "core/Merger.h"
#include "core/Metadata.h"
#include "format/KeePass2Reader.h"
#include "keys/PasswordKey.h"

#include <QDebug>
#include <QFileInfo>
#include <QIcon>
#include <QPainter>
#include <QStringBuilder>

static const QString KeeShareExt_ExportEnabled("Export");
static const QString KeeShareExt_ImportEnabled("Import");
static const QString KeeShareExt("KeeShareXC");
static const QChar KeeShareExt_referencePropertyDelimiter('|');

DatabaseSharing::DatabaseSharing(Database* db, QObject* parent)
    : QObject(parent)
    , m_db(db)
{
    connect(m_db, SIGNAL(modified()), this, SLOT(handleChanged()));
    connect(&m_fileWatcher, SIGNAL(fileChanged(QString)), this, SLOT(handleFileChanged(QString)));
    connect(&m_fileWatcher, SIGNAL(directoryChanged(QString)), this, SLOT(handleDirectoryChanged(QString)));
    connect(&m_fileWatchUnblockTimer, SIGNAL(timeout()), this, SLOT(unblockAutoReload()));
    m_fileWatchUnblockTimer.setSingleShot(true);
}

void DatabaseSharing::deinitialize()
{
    for (Reference reference : m_groupToReference.values()) {
        QFileInfo info(reference.path);
        m_fileWatcher.removePath(info.absoluteFilePath());
        m_fileWatcher.removePath(info.absolutePath());
    }
    m_watched.clear();
    m_sources.clear();
    m_groupToReference.clear();
    m_referenceToGroup.clear();
}

void DatabaseSharing::reinitialize()
{
    struct Update
    {
        Group* group;
        Reference oldReference;
        Reference newReference;
    };
    QList<Update> updated;
    QList<Group*> groups = m_db->rootGroup()->groupsRecursive(true);
    for (Group* group : groups) {
        Update couple{group, m_groupToReference.value(group), referenceOf(group->customData())};
        if (couple.oldReference == couple.newReference) {
            continue;
        }
        m_groupToReference.remove(couple.group);
        m_referenceToGroup.remove(couple.oldReference);
        m_shareToGroup.remove(couple.oldReference.path);
        if (couple.newReference.isActive() && isEnabled(m_db, couple.newReference.type)) {
            m_groupToReference[couple.group] = couple.newReference;
            m_referenceToGroup[couple.newReference] = couple.group;
            m_shareToGroup[couple.newReference.path] = couple.group;
        }
        updated << couple;
    }

    QStringList success;
    QStringList warning;
    QStringList error;
    for (Update couple : updated) {
        if (!couple.oldReference.path.isEmpty()) {
            const QFileInfo info(couple.oldReference.path);
            m_fileWatcher.removePath(info.absoluteFilePath());
            m_fileWatcher.removePath(info.absolutePath());
            m_watched.remove(info.absoluteFilePath());
            m_sources[info.absolutePath()].remove(info.fileName());
        }
        if (!couple.newReference.path.isEmpty()) {
            const QFileInfo info(couple.newReference.path);
            m_fileWatcher.addPath(info.absoluteFilePath());
            m_fileWatcher.addPath(info.absolutePath());
            m_watched[info.absoluteFilePath()] = info.exists();
            m_sources[info.absolutePath()].insert(info.fileName());
        }

        if (couple.newReference.isImporting()) {
            const Result result = this->handleReferenceChanged(couple.newReference.path);
            if (!result.isValid()) {
                // tolerable result - blocked import or missing source
                continue;
            }

            if (result.isError()) {
                error << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
            } else if (result.isWarning()) {
                warning << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
            } else if (result.isInfo()) {
                success << tr("Import from %1 successful (%2)").arg(result.path).arg(result.message);
            } else {
                success << tr("Imported from %1").arg(result.path);
            }
        }
    }
    notifyAbout(success, warning, error);
}

void DatabaseSharing::notifyAbout(const QStringList& success, const QStringList& warning, const QStringList& error)
{
    if (error.isEmpty() && warning.isEmpty() && success.isEmpty()) {
        return;
    }

    MessageWidget::MessageType type = MessageWidget::Positive;
    if (!warning.isEmpty()) {
        type = MessageWidget::Warning;
    }
    if (!error.isEmpty()) {
        type = MessageWidget::Error;
    }
    emit sharingChanged((success + warning + error).join("\n"), type);
}

void DatabaseSharing::handleChanged()
{
    if (!m_db) {
        Q_ASSERT(m_db);
        return;
    }
    if (!isEnabled(m_db)) {
        deinitialize();
    } else {
        reinitialize();
    }
}

bool DatabaseSharing::isExporting(const Database* database, const Group* group)
{
    if (!isEnabled(database, ExportTo)) {
        return false;
    }
    const Reference reference = referenceOf(group->customData());
    return reference.isExporting();
}

bool DatabaseSharing::isImporting(const Database* database, const Group* group)
{
    if (!isEnabled(database, ImportFrom)) {
        return false;
    }
    const Reference reference = referenceOf(group->customData());
    return reference.isImporting();
}

bool DatabaseSharing::isShared(const Group* group)
{
    return group->customData()->contains(KeeShareExt);
}

DatabaseSharing::Reference DatabaseSharing::referenceOf(const CustomData* customData)
{
    static const Reference s_emptyReference;
    if (!customData->contains(KeeShareExt)) {
        return s_emptyReference;
    }
    return deserializeReference(customData->value(KeeShareExt));
}

void DatabaseSharing::setReferenceTo(CustomData* customData, const DatabaseSharing::Reference& reference)
{
    if (reference.isNull()) {
        customData->remove(KeeShareExt);
    } else {
        customData->set(KeeShareExt, serializeReference(reference));
    }
}

void DatabaseSharing::removeReferenceFrom(CustomData* customData)
{
    setReferenceTo(customData, Reference());
}

QPixmap DatabaseSharing::sharingIndicatorBadge(const Group* group, QPixmap pixmap)
{
    if (!isShared(group)) {
        return pixmap;
    }
    const Reference reference = referenceOf(group->customData());
    const bool enabled = isEnabled(group->database(), reference.type)
                         && (isImporting(group->database(), group) || isExporting(group->database(), group));
    const QPixmap badge = enabled ? databaseIcons()->iconPixmap(DatabaseIcons::SharedIconIndex)
                                  : databaseIcons()->iconPixmap(DatabaseIcons::UnsharedIconIndex);
    QImage canvas = pixmap.toImage();
    const QRectF target(canvas.width() * 0.4, canvas.height() * 0.4, canvas.width() * 0.6, canvas.height() * 0.6);
    QPainter painter(&canvas);
    painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
    painter.drawPixmap(target, badge, badge.rect());
    pixmap.convertFromImage(canvas);
    return pixmap;
}

QString DatabaseSharing::referenceTypeLabel(const Reference& reference)
{
    switch (reference.type) {
    case DatabaseSharing::Inactive:
        return tr("Disabled share");
    case DatabaseSharing::ImportFrom:
        return tr("Import from");
    case DatabaseSharing::ExportTo:
        return tr("Export to");
    case DatabaseSharing::SynchronizeWith:
        return tr("Synchronize with");
    }
    return "";
}

QString DatabaseSharing::sharingIndicatorSuffix(const Group* group, const QString& text)
{
    Q_UNUSED(group);
    return text;
    //    if (!isShared(group)) {
    //        return text;
    //    }
    //    const Reference reference = referenceOf(group->customData());
    //    return reference.isActive()
    //               ? tr("%1 [share active]", "Template for name with active sharing annotation").arg(text)
    //               : tr("%1 [share inactive]", "Template for name with inactive sharing annotation").arg(text);
}

void DatabaseSharing::handleFileChanged(const QString& path)
{
    qDebug("File changed %s", qPrintable(path));
    const QFileInfo info(path);
    qDebug("Refresh file %s", qPrintable(info.absoluteFilePath()));
    m_fileWatcher.addPath(path);
    const Result result = this->handleReferenceChanged(path);
    if (!result.isValid()) {
        return;
    }
    QStringList success;
    QStringList warning;
    QStringList error;
    if (result.isError()) {
        error << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
    } else if (result.isWarning()) {
        warning << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
    } else if (result.isInfo()) {
        success << tr("Import from %1 successful (%2)").arg(result.path).arg(result.message);
    } else {
        success << tr("Imported from %1").arg(result.path);
    }
    notifyAbout(success, warning, error);
}

DatabaseSharing::Result DatabaseSharing::handleReferenceChanged(const QString& path)
{
    if (!isEnabled(m_db, ImportFrom)) {
        return {};
    }
    QPointer<Group> shareGroup = m_shareToGroup.value(path);
    if (!shareGroup) {
        qWarning("Source for %s does not exist", qPrintable(path));
        Q_ASSERT(shareGroup);
        return {};
    }
    const Reference reference = referenceOf(shareGroup->customData());
    QFileInfo info(reference.path);
    if (m_blockedPaths[info.canonicalFilePath()] > Clock::currentDateTimeUtc()) {
        qDebug("Ignore blocked change of reference %s", qPrintable(reference.path));
        return {};
    }
    if (reference.type == Inactive) {
        qDebug("Ignore change of inactive reference %s", qPrintable(reference.path));
        return {};
    }
    if (reference.type == ExportTo) {
        qDebug("Ignore change of export reference %s", qPrintable(reference.path));
        return {};
    }

    QFile dbFile(info.absoluteFilePath());
    if (!dbFile.exists()) {
        qCritical("File %s does not exist.", qPrintable(info.absoluteFilePath()));
        return {reference.path, Result::Warning, tr("File does not exist")};
    }
    if (!dbFile.open(QIODevice::ReadOnly)) {
        qCritical("Unable to open file %s.", qPrintable(info.absoluteFilePath()));
        return {reference.path, Result::Error, tr("File is not readable")};
    }

    KeePass2Reader reader;
    CompositeKey key;
    key.addKey(PasswordKey(reference.password));
    Database* sourceDb = reader.readDatabase(&dbFile, key);
    if (reader.hasError()) {
        qCritical("Error while parsing the database: %s", qPrintable(reader.errorString()));
        return {reference.path, Result::Error, reader.errorString()};
    }

    Database* targetDb = m_db;
    Group* targetGroup = targetDb->rootGroup()->findGroupByUuid(shareGroup->uuid());
    Q_ASSERT(targetGroup == shareGroup);
    qDebug("Synchronize %s %s with %s",
           qPrintable(reference.path),
           qPrintable(targetGroup->name()),
           qPrintable(sourceDb->rootGroup()->name()));
    Merger merger(sourceDb->rootGroup(), targetGroup);
    merger.setForcedMergeMode(Group::Synchronize);
    const bool changed = merger.merge();
    if (changed) {
        return {reference.path};
    }
    return {};
}

void DatabaseSharing::handleDirectoryChanged(const QString& path)
{
    QStringList success;
    QStringList warning;
    QStringList error;
    qDebug("Directory changed %s", qPrintable(path));
    for (QString file : m_sources[path]) {
        QFileInfo info(path + "/" + file);
        if (!info.exists()) {
            qDebug("Remove watch file %s", qPrintable(info.absoluteFilePath()));
            m_fileWatcher.removePath(info.absolutePath());
            warning << tr("Import file %1 removed").arg(info.absoluteFilePath());
        }
        if (!m_watched[info.absoluteFilePath()]) {
            qDebug("Add watch file %s", qPrintable(info.absoluteFilePath()));
            m_fileWatcher.addPath(info.absolutePath());
            const Result message = this->handleReferenceChanged(info.absoluteFilePath());
            if (message.isError()) {
                error << tr("Import from %1 failed (%2)").arg(message.path).arg(message.message);
            } else if (message.isWarning()) {
                warning << tr("Import from %1 failed (%2)").arg(message.path).arg(message.message);
            } else if (message.isInfo()) {
                success << tr("Imported from %1 successful (%2").arg(message.path).arg(message.message);
            } else {
                success << tr("Imported from %1").arg(message.path);
            }
        }
        if (m_watched[info.absoluteFilePath()] && info.exists()) {
            qDebug("Refresh watch file %s", qPrintable(info.absoluteFilePath()));
            m_fileWatcher.removePath(info.absolutePath());
            m_fileWatcher.addPath(info.absolutePath());
            // this->handleReferenceChanged(info.absoluteFilePath());
        }
        m_watched[info.absoluteFilePath()] = info.exists();
    }
    notifyAbout(success, warning, error);
}

void DatabaseSharing::unblockAutoReload()
{
    const QDateTime current = Clock::currentDateTimeUtc();
    int timeout = 0;
    for (QString key : m_blockedPaths.keys()) {
        if (m_blockedPaths[key] < current) {
            // We assume that there was no concurrent change of the database
            // during our block - so no need to reimport
            qDebug("Remove block from %s", qPrintable(key));
            m_blockedPaths.remove(key);
            continue;
        }
        qDebug("Keep block from %s", qPrintable(key));
        timeout = static_cast<int>(current.msecsTo(m_blockedPaths[key]));
    }
    if (timeout > 0 && !m_fileWatchUnblockTimer.isActive()) {
        m_fileWatchUnblockTimer.start(timeout);
    }
}

DatabaseSharing::Reference DatabaseSharing::deserializeReference(const QString& raw)
{
    const auto parts = raw.split(KeeShareExt_referencePropertyDelimiter);
    if (parts.count() != 4) {
        qWarning("Invalid sharing reference detected - sharing disabled");
        return Reference();
    }
    const auto type = static_cast<Type>(parts[0].toInt());
    const auto uuid = Uuid::fromHex(parts[1]);
    const auto path = QByteArray::fromBase64(parts[2].toLatin1());
    const auto password = QByteArray::fromBase64(parts[3].toLatin1());
    return Reference(type, uuid, path, password);
}

QString DatabaseSharing::serializeReference(const DatabaseSharing::Reference& reference)
{
    const QStringList raw = QStringList() << QString::number(static_cast<int>(reference.type)) << reference.uuid.toHex()
                                          << reference.path.toLatin1().toBase64()
                                          << reference.password.toLatin1().toBase64();
    return raw.join(KeeShareExt_referencePropertyDelimiter);
}

void DatabaseSharing::resolveReferenceAttributes(Entry* targetEntry, Database* sourceDb)
{
    for (const QString& attribute : EntryAttributes::DefaultAttributes) {
        const QString standardValue = targetEntry->attributes()->value(attribute);
        Entry::PlaceholderType type = targetEntry->placeholderType(standardValue);
        if (type != Entry::PlaceholderType::Reference) {
            // No reference to resolve
            continue;
        }
        const Entry* referencedTargetEntry = targetEntry->resolveReference(standardValue);
        if (referencedTargetEntry) {
            // References is within scope, no resolving needed
            continue;
        }
        // We could do more sophisticated **** trying to point the reference to the next in-scope reference
        // but those cases with high propability constructed examples and very rare in real usage
        const Entry* sourceReference = sourceDb->resolveEntry(targetEntry->uuid());
        const QString resolvedValue = sourceReference->resolveMultiplePlaceholders(standardValue);
        targetEntry->setUpdateTimeinfo(false);
        targetEntry->attributes()->set(attribute, resolvedValue, targetEntry->attributes()->isProtected(attribute));
        targetEntry->setUpdateTimeinfo(true);
    }
}

DatabaseSharing::Result DatabaseSharing::exportSharedFrom(Group* sourceRoot)
{
    Reference reference = referenceOf(sourceRoot->customData());
    if (reference.path.isEmpty()) {
        qWarning(
            "Invalid export path in %s (%s)", qPrintable(sourceRoot->name()), qPrintable(sourceRoot->uuid().toHex()));
        return {reference.path, Result::Warning, tr("Export without path for %1 impossible").arg(sourceRoot->name())};
    }
    QFileInfo info(reference.path);
    qDebug("Export blocking %s to %s", qPrintable(sourceRoot->name()), qPrintable(reference.path));
    m_blockedPaths[info.canonicalFilePath()] = Clock::currentDateTimeUtc().addMSecs(500);
    if (!m_fileWatchUnblockTimer.isActive()) {
        m_fileWatchUnblockTimer.start(500);
    }
    Database* sourceDb = sourceRoot->database();
    QScopedPointer<Database> targetDb(new Database());
    targetDb->metadata()->setRecycleBinEnabled(false);
    CompositeKey key;
    key.addKey(PasswordKey(reference.password));

    // Copy the source root as the root of the export database, memory manage the old root node
    Group* targetRoot = sourceRoot->clone(Entry::CloneNoFlags, Group::CloneNoFlags);
    const bool updateTimeinfo = targetRoot->canUpdateTimeinfo();
    targetRoot->setUpdateTimeinfo(false);
    targetRoot->customData()->remove(KeeShareExt);
    targetRoot->setUpdateTimeinfo(updateTimeinfo);
    const QList<Entry*> sourceEntries = sourceRoot->entriesRecursive(false);
    for (const Entry* sourceEntry : sourceEntries) {
        Entry* targetEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
        const bool updateTimeinfo = targetEntry->canUpdateTimeinfo();
        targetEntry->setUpdateTimeinfo(false);
        targetEntry->setGroup(targetRoot);
        targetEntry->setUpdateTimeinfo(updateTimeinfo);
        const Uuid iconUuid = targetEntry->iconUuid();
        if (!iconUuid.isNull()) {
            targetDb->metadata()->addCustomIcon(iconUuid, sourceEntry->icon());
        }
    }

    targetDb->setKey(key);
    Group* obsoleteRoot = targetDb->rootGroup();
    targetDb->setRootGroup(targetRoot);
    delete obsoleteRoot;

    targetDb->metadata()->setName(sourceRoot->name());
    // Push all deletions of the source database to the target
    // simple moving out of a share group will not trigger a deletion in the
    // target - a more elaborate mechanism may need the use of another custom
    // attribute to share unshared entries from the target db
    for (const DeletedObject& object : sourceDb->deletedObjects()) {
        targetDb->addDeletedObject(object);
    }
    for (Entry* targetEntry : targetRoot->entriesRecursive(false)) {
        if (targetEntry->hasReferences()) {
            resolveReferenceAttributes(targetEntry, sourceDb);
        }
    }
    QString errorMessage = targetDb->saveToFile(reference.path);
    if (!errorMessage.isEmpty()) {
        //  emit messageTab(tr("Writing the database failed.").append("\n").append(errorMessage), MessageWidget::Error);
        qWarning("Writing export dabase failed: %s.", errorMessage.toLatin1().data());
        return {reference.path, Result::Error, errorMessage};
    }
    return {reference.path};
}

bool DatabaseSharing::isEnabled(const Database* db)
{
    return isEnabled(db, SynchronizeWith);
}

bool DatabaseSharing::isEnabled(const Database* db, DatabaseSharing::Type type)
{
    if (!db) {
        return false;
    }
    auto* meta = db->metadata();
    auto* customData = meta->customData();
    bool enabled = false;
    if (type == SynchronizeWith || type == ExportTo) {
        enabled |= customData->value(KeeShareExt).contains(KeeShareExt_ExportEnabled, Qt::CaseInsensitive);
    }
    if (type == SynchronizeWith || type == ImportFrom) {
        enabled |= customData->value(KeeShareExt).contains(KeeShareExt_ImportEnabled, Qt::CaseInsensitive);
    }
    return enabled;
}

void DatabaseSharing::enable(Database* db, DatabaseSharing::Type sharing)
{
    QStringList options;
    if ((sharing & ImportFrom) == ImportFrom) {
        options << KeeShareExt_ImportEnabled;
    }
    if ((sharing & ExportTo) == ExportTo) {
        options << KeeShareExt_ExportEnabled;
    }
    auto* meta = db->metadata();
    auto* customData = meta->customData();
    if (options.isEmpty()) {
        customData->remove(KeeShareExt);
    } else {
        customData->set(KeeShareExt, options.join("|"));
    }
}

QList<Group*> DatabaseSharing::shares() const
{
    QList<Group*> groups;
    for (const QPointer<Group>& group : m_groupToReference.keys()) {
        if (group) {
            groups << group;
        }
    }
    return groups;
}

void DatabaseSharing::exportSharedEntries()
{
    if (!isEnabled(m_db, ExportTo)) {
        return;
    }
    QList<Result> results;
    QList<Group*> groups = m_db->rootGroup()->groupsRecursive(true);
    for (Group* group : groups) {
        const Reference reference = referenceOf(group->customData());
        if (reference.isExporting()) {
            results << exportSharedFrom(group);
        }
    }
    QStringList error;
    QStringList warning;
    QStringList success;
    for (const Result& result : results) {
        if (!result.isValid()) {
            Q_ASSERT(result.isValid());
            continue;
        }
        if (result.isError()) {
            error << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
        } else if (result.isWarning()) {
            warning << tr("Import from %1 failed (%2)").arg(result.path).arg(result.message);
        } else if (result.isInfo()) {
            success << tr("Import from %1 successful (%2)").arg(result.path).arg(result.message);
        } else {
            success << tr("Imported from %1").arg(result.path);
        }
    }
    notifyAbout(success, warning, error);
}

DatabaseSharing::Reference::Reference(DatabaseSharing::Type type,
                                      const Uuid& uuid,
                                      const QString& path,
                                      const QString& password)
    : type(type)
    , uuid(uuid)
    , path(path)
    , password(password)
{
}

bool DatabaseSharing::Reference::isNull() const
{
    return type == Inactive && path.isEmpty() && password.isEmpty();
}

bool DatabaseSharing::Reference::isActive() const
{
    return type != Inactive && !path.isEmpty();
}

bool DatabaseSharing::Reference::isExporting() const
{
    return (type & ExportTo) != 0 && !path.isEmpty();
}

bool DatabaseSharing::Reference::isImporting() const
{
    return (type & ImportFrom) != 0 && !path.isEmpty();
}

bool DatabaseSharing::Reference::operator<(const DatabaseSharing::Reference& other) const
{
    if (type != other.type) {
        return type < other.type;
    }
    return path < other.path;
}

bool DatabaseSharing::Reference::operator==(const DatabaseSharing::Reference& other) const
{
    return path == other.path && uuid == other.uuid && password == other.password && type == other.type;
}

bool DatabaseSharing::Result::isValid() const
{
    return !path.isEmpty() || !message.isEmpty() || !message.isEmpty() || !message.isEmpty();
}

bool DatabaseSharing::Result::isError() const
{
    return !message.isEmpty() && type == Error;
}

bool DatabaseSharing::Result::isInfo() const
{
    return !message.isEmpty() && type == Info;
}

bool DatabaseSharing::Result::isWarning() const
{
    return !message.isEmpty() && type == Warning;
}
