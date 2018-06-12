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
#include "core/FileWatcher.h"
#include "core/Group.h"
#include "core/Merger.h"
#include "core/Metadata.h"
#include "format/KdbxXmlWriter.h"
#include "format/KeePass2RandomStream.h"
#include "format/KeePass2Reader.h"
#include "keys/PasswordKey.h"
#include <iostream>

#include <QBuffer>
#include <QDebug>
#include <QFileInfo>
#include <QIcon>
#include <QPainter>
#include <QStringBuilder>

#include <gcrypt.h>

#include <crypto/OpenSSHKey.h>
#include <crypto/Signature.h>

static const QString KeeShareExt_ExportEnabled("Export");
static const QString KeeShareExt_ImportEnabled("Import");
static const QString KeeShareExt("KeeShareXC");
static const QString KeeShareExt_Source("KeeShareXC_Source");
static const QString KeeShareExt_Certificate("KeeShareXC_Certificate");
static const QString KeeShareExt_Signature("KeeShareXC_Signature");
static const QChar KeeShareExt_referencePropertyDelimiter('|');

DatabaseSharing::DatabaseSharing(Database* db, QObject* parent)
    : QObject(parent)
    , m_db(db)
    , m_fileWatcher(new BulkFileWatcher(this))
{
    connect(m_db, SIGNAL(modified()), this, SLOT(handleDatabaseChanged()));
    connect(m_fileWatcher, SIGNAL(fileCreated(QString)), this, SLOT(handleFileCreated(QString)));
    connect(m_fileWatcher, SIGNAL(fileChanged(QString)), this, SLOT(handleFileChanged(QString)));
    connect(m_fileWatcher, SIGNAL(fileRemoved(QString)), this, SLOT(handleFileRemoved(QString)));
}

DatabaseSharing::~DatabaseSharing()
{
}

void DatabaseSharing::deinitialize()
{
    m_fileWatcher->clear();
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
    for (Update update : updated) {
        if (!update.oldReference.path.isEmpty()) {
            m_fileWatcher->removePath(update.oldReference.path);
        }
        if (!update.newReference.path.isEmpty() && update.newReference.type != Inactive) {
            m_fileWatcher->addPath(update.newReference.path);
        }

        if (update.newReference.isImporting()) {
            const Result result = this->importFromReferenceContainer(update.newReference.path);
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

void DatabaseSharing::handleDatabaseChanged()
{
    if (!m_db) {
        Q_ASSERT(m_db);
        return;
    }
    if (!isEnabled(m_db, ExportTo) && !isEnabled(m_db, ImportFrom)) {
        deinitialize();
    } else {
        reinitialize();
    }
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
        return;
    }
    if (customData->contains(KeeShareExt)) {
        customData->set(KeeShareExt, serializeReference(reference));
    }
    customData->set(KeeShareExt, serializeReference(reference));
}

QPixmap DatabaseSharing::indicatorBadge(const Group* group, QPixmap pixmap)
{
    if (!isShared(group)) {
        return pixmap;
    }
    const Reference reference = referenceOf(group->customData());
    const bool enabled = isEnabled(group->database(), reference.type);
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

void DatabaseSharing::assignDefaultsTo(DatabaseSharing::Reference &reference)
{
    OpenSSHKey signatureKey = OpenSSHKey::generate();
    signatureKey.openKey(QString());
    QStringList certificate = QStringList() << "rsa" << "verified";
    for( const QByteArray& part : signatureKey.publicParts() ){
        certificate << part.toHex();
    }
    QStringList key = QStringList() << "rsa";
    for( const QByteArray& part : signatureKey.privateParts() ){
        key << part.toHex();
    }
    reference.certificates << QString::fromLatin1(certificate.join(KeeShareExt_referencePropertyDelimiter).toLatin1().toBase64());
    reference.key = key.join(KeeShareExt_referencePropertyDelimiter).toLatin1().toBase64();
    reference.signer = "KeeShare-Signer";
}

QString DatabaseSharing::indicatorSuffix(const Group* group, const QString& text)
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

void DatabaseSharing::handleFileUpdated(const QString& path, Change change)
{
    switch (change) {
    case Creation:
        qDebug("File created %s", qPrintable(path));
        break;
    case Update:
        qDebug("File changed %s", qPrintable(path));
        break;
    case Deletion:
        qDebug("File deleted %s", qPrintable(path));
        break;
    }

    const Result result = this->importFromReferenceContainer(path);
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

void DatabaseSharing::handleFileCreated(const QString& path)
{
    handleFileUpdated(path, Creation);
}

void DatabaseSharing::handleFileChanged(const QString& path)
{
    handleFileUpdated(path, Update);
}

void DatabaseSharing::handleFileRemoved(const QString& path)
{
    handleFileUpdated(path, Deletion);
}

bool DatabaseSharing::unsign(Database* db, const Reference& reference)
{
    QVariantMap map = db->publicCustomData();
    QString publicKey = map[KeeShareExt_Certificate].toString();
    // TODO CK: Let the user decide if the certificate is trustworthy
    Reference copy = reference;
    copy.certificates << publicKey;
    if( !copy.certificates.contains(publicKey)){
        ::qWarning() << "Unverified public key of" << map[KeeShareExt_Source];
        return false;
    }
    QString signature = QByteArray::fromBase64(map[KeeShareExt_Signature].toString().toLatin1());
    ::qDebug() << ">> IMPORT" << signature;
    map[KeeShareExt_Signature] = QString();
    db->setPublicCustomData(map);

    // TODO HNH is it sufficient to hard code just one algorithm to create a signature?
    // TODO HNH it would be better to use standard formats like real certificates and ANS1 formats to sign our data -
    // but that would possibly need an ASN1 lib
    QByteArray buffer;
    QBuffer device(&buffer);
    device.open(QBuffer::ReadWrite);
    QByteArray headerHash;
    KeePass2RandomStream randomStream(KeePass2::ProtectedStreamAlgo::ChaCha20);
    KdbxXmlWriter xmlWriter(KeePass2::FILE_VERSION_4);
    xmlWriter.writeDatabase(&device, db, &randomStream, headerHash);

    Signature signer;
    OpenSSHKey key;
    QStringList parts = QString::fromLatin1(QByteArray::fromBase64(publicKey.toLatin1())).split(KeeShareExt_referencePropertyDelimiter);
    Q_ASSERT(parts[0] == "rsa");
    Q_ASSERT(parts[1] == "verified");
    QList<QByteArray> publicData;
    for( int i = 2; i < parts.count(); ++i ){
        publicData << QByteArray::fromHex(parts[i].toLatin1());
    }
    key.m_rawType = OpenSSHKey::TYPE_RSA_PUBLIC;
    key.setPublicData(publicData);
    key.openKey(QString());
    bool success = signer.verify(buffer, signature, key);
    map.remove(KeeShareExt_Signature);
    map.remove(KeeShareExt_Certificate);
    map.remove(KeeShareExt_Source);
    db->setPublicCustomData(map);
    return success;
}

DatabaseSharing::Result DatabaseSharing::importContainerInto(const Reference& reference, Group* targetGroup)
{
    const QFileInfo info(reference.path);
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

    if (!unsign(sourceDb, reference)) {
        qCritical("Invalid signature of database");
        return {reference.path, Result::Error, tr("Invalid signature") };
    }

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

DatabaseSharing::Result DatabaseSharing::importFromReferenceContainer(const QString& path)
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
    if (reference.type == Inactive) {
        qDebug("Ignore change of inactive reference %s", qPrintable(reference.path));
        return {};
    }
    if (reference.type == ExportTo) {
        qDebug("Ignore change of export reference %s", qPrintable(reference.path));
        return {};
    }
    Q_ASSERT(shareGroup->database() == m_db);
    Q_ASSERT(shareGroup == m_db->rootGroup()->findGroupByUuid(shareGroup->uuid()));
    return importContainerInto(reference, shareGroup);
}

DatabaseSharing::Reference DatabaseSharing::deserializeReference(const QString& raw)
{
    const auto parts = raw.split(KeeShareExt_referencePropertyDelimiter);
    if (parts.count() != 7) {
        qWarning("Invalid sharing reference detected - sharing disabled");
        return Reference();
    }
    const auto type = static_cast<Type>(parts[0].toInt());
    const auto uuid = Uuid::fromHex(parts[1]);
    const auto path = QByteArray::fromBase64(parts[2].toLatin1());
    const auto password = QByteArray::fromBase64(parts[3].toLatin1());
    const auto certificates = QString::fromLatin1(QByteArray::fromBase64(parts[4].toLatin1())).split(KeeShareExt_referencePropertyDelimiter);
    const auto key = QByteArray::fromBase64(parts[5].toLatin1());
    const auto signer = QByteArray::fromBase64(parts[6].toLatin1());
    return Reference(type, uuid, path, password, certificates, key, signer);
}

QString DatabaseSharing::serializeReference(const DatabaseSharing::Reference& reference)
{
    const QStringList raw = QStringList() << QString::number(static_cast<int>(reference.type))
                                          << reference.uuid.toHex()
                                          << reference.path.toLatin1().toBase64()
                                          << reference.password.toLatin1().toBase64()
                                          << reference.certificates.join(KeeShareExt_referencePropertyDelimiter).toLatin1().toBase64()
                                          << reference.key.toLatin1().toBase64()
                                          << reference.signer.toLatin1().toBase64();
    return raw.join(KeeShareExt_referencePropertyDelimiter);
}

void DatabaseSharing::resolveReferenceAttributes(Entry* targetEntry, const Database* sourceDb)
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

void DatabaseSharing::sign(Database* db, const Reference& reference)
{
    QVariantMap map = db->publicCustomData();
    map[KeeShareExt_Source] = reference.signer;
    map[KeeShareExt_Certificate] = reference.certificates.first();
    map[KeeShareExt_Signature] = QString();
    db->setPublicCustomData(map);

    // TODO HNH is it sufficient to hard code just one algorithm to create a signature?
    // TODO HNH it would be better to use standard formats like real certificates and ANS1 formats to sign our data -
    // but that would possibly need an ASN1 lib
    QByteArray buffer;
    QBuffer device(&buffer);
    device.open(QBuffer::ReadWrite);
    QByteArray headerHash;
    KeePass2RandomStream randomStream(KeePass2::ProtectedStreamAlgo::ChaCha20);
    KdbxXmlWriter xmlWriter(KeePass2::FILE_VERSION_4);
    xmlWriter.writeDatabase(&device, db, &randomStream, headerHash);

    Signature signer;
    OpenSSHKey key;
    QList<QByteArray> privateData;
    QString privateKey = QString::fromLatin1(QByteArray::fromBase64(reference.key.toLatin1()));
    QStringList parts = privateKey.split(KeeShareExt_referencePropertyDelimiter);
    Q_ASSERT(parts[0] == "rsa");
    for( int i = 1; i < parts.count(); ++i){
        privateData << QByteArray::fromHex(parts[i].toLatin1());
    }
    key.m_rawType = OpenSSHKey::TYPE_RSA_PRIVATE;
    key.setPrivateData(privateData);
    key.openKey(QString());
    QString signature = signer.create(buffer, key).toLatin1().toBase64();
    ::qDebug() << ">> EXPORT" << signature;
    map[KeeShareExt_Signature] = signature;

    db->setPublicCustomData(map);
}

Database* DatabaseSharing::exportIntoContainer(const Reference& reference, const Group* sourceRoot)
{
    const Database* sourceDb = sourceRoot->database();
    Database* targetDb(new Database());
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
    sign(targetDb, reference);
    return targetDb;
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

const Database* DatabaseSharing::database() const
{
    return m_db;
}

Database* DatabaseSharing::database()
{
    return m_db;
}

void DatabaseSharing::handleDatabaseOpened()
{
    if (!m_db) {
        Q_ASSERT(m_db);
        return;
    }
    if (!isEnabled(m_db, ExportTo) && !isEnabled(m_db, ImportFrom)) {
        deinitialize();
    } else {
        reinitialize();
    }
}

QList<DatabaseSharing::Result> DatabaseSharing::exportIntoReferenceContainers()
{
    QList<Result> results;
    const QList<Group*> groups = m_db->rootGroup()->groupsRecursive(true);
    for (const Group* group : groups) {
        const Reference reference = referenceOf(group->customData());
        if (!reference.isExporting()) {
            continue;
        }

        m_fileWatcher->ignoreFileChanges(reference.path);
        QScopedPointer<Database> targetDb(exportIntoContainer(reference, group));
        const QString errorMessage = targetDb->saveToFile(reference.path);
        m_fileWatcher->observeFileChanges(true);

        if (!errorMessage.isEmpty()) {
            qWarning("Writing export dabase failed: %s.", errorMessage.toLatin1().data());
            results << Result{reference.path, Result::Error, errorMessage};
            continue;
        }
        results << Result{reference.path};
    }
    return results;
}

void DatabaseSharing::handleDatabaseSaved()
{
    if (!isEnabled(m_db, ExportTo)) {
        return;
    }
    const QList<Result> results = exportIntoReferenceContainers();
    QStringList error;
    QStringList warning;
    QStringList success;
    for (const Result& result : results) {
        if (!result.isValid()) {
            Q_ASSERT(result.isValid());
            continue;
        }
        if (result.isError()) {
            error << tr("Export to %1 failed (%2)").arg(result.path).arg(result.message);
        } else if (result.isWarning()) {
            warning << tr("Export to %1 failed (%2)").arg(result.path).arg(result.message);
        } else if (result.isInfo()) {
            success << tr("Export to %1 successful (%2)").arg(result.path).arg(result.message);
        } else {
            success << tr("Export to %1").arg(result.path);
        }
    }
    notifyAbout(success, warning, error);
}

DatabaseSharing::Reference::Reference()
    : type(Type::Inactive)
    , uuid(Uuid::random())
{
}

DatabaseSharing::Reference::Reference(DatabaseSharing::Type type,
                                      const Uuid& uuid,
                                      const QString& path,
                                      const QString& password,
                                      const QStringList &certificates,
                                      const QString &key,
                                      const QString &signer)
    : type(type)
    , uuid(uuid)
    , path(path)
    , password(password)
    , certificates(certificates)
    , key(key)
    , signer(signer)
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

DatabaseSharing::Result::Result(const QString& path, DatabaseSharing::Result::Type type, const QString& message)
    : path(path)
    , type(type)
    , message(message)
{
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
