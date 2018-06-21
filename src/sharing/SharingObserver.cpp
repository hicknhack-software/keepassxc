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

#include "SharingObserver.h"
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
#include "format/KeePass2Reader.h"
#include "format/KeePass2Writer.h"
#include "gui/MessageBox.h"
#include "keys/PasswordKey.h"
#include "sharing/Signature.h"
#include "sshagent/OpenSSHKey.h"

#include <iostream>

#include <QBuffer>
#include <QDebug>
#include <QFileInfo>
#include <QIcon>
#include <QPainter>
#include <QStringBuilder>

#include <gcrypt.h>
#include <quazip5/quazip.h>
#include <quazip5/quazipfile.h>

namespace {

static const QString KeeShareExt_Signature("container.share.signature");
static const QString KeeShareExt_Container("container.share.kdbx");

}

SharingObserver::SharingObserver(Database* db, QObject* parent)
    : QObject(parent)
    , m_db(db)
    , m_fileWatcher(new BulkFileWatcher(this))
{
    connect(m_db, SIGNAL(modified()), this, SLOT(handleDatabaseChanged()));
    connect(m_fileWatcher, SIGNAL(fileCreated(QString)), this, SLOT(handleFileCreated(QString)));
    connect(m_fileWatcher, SIGNAL(fileChanged(QString)), this, SLOT(handleFileChanged(QString)));
    connect(m_fileWatcher, SIGNAL(fileRemoved(QString)), this, SLOT(handleFileRemoved(QString)));
}

SharingObserver::~SharingObserver()
{
}

void SharingObserver::deinitialize()
{
    m_fileWatcher->clear();
    m_groupToReference.clear();
    m_referenceToGroup.clear();
}

void SharingObserver::reinitialize()
{
    struct Update
    {
        Group* group;
        Sharing::Reference oldReference;
        Sharing::Reference newReference;
    };
    QList<Update> updated;
    QList<Group*> groups = m_db->rootGroup()->groupsRecursive(true);
    for (Group* group : groups) {
        Update couple{group, m_groupToReference.value(group), Sharing::referenceOf(group->customData())};
        if (couple.oldReference == couple.newReference) {
            continue;
        }
        m_groupToReference.remove(couple.group);
        m_referenceToGroup.remove(couple.oldReference);
        m_shareToGroup.remove(couple.oldReference.path);
        if (couple.newReference.isActive() && Sharing::isEnabled(m_db, couple.newReference.type)) {
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
        if (!update.newReference.path.isEmpty() && update.newReference.type != Sharing::Inactive) {
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

void SharingObserver::notifyAbout(const QStringList& success, const QStringList& warning, const QStringList& error)
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

void SharingObserver::handleDatabaseChanged()
{
    if (!m_db) {
        Q_ASSERT(m_db);
        return;
    }
    if (!Sharing::isEnabled(m_db, Sharing::ExportTo) && !Sharing::isEnabled(m_db, Sharing::ImportFrom)) {
        deinitialize();
    } else {
        reinitialize();
    }
}

void SharingObserver::handleFileUpdated(const QString& path, Change change)
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

void SharingObserver::handleFileCreated(const QString& path)
{
    handleFileUpdated(path, Creation);
}

void SharingObserver::handleFileChanged(const QString& path)
{
    handleFileUpdated(path, Update);
}

void SharingObserver::handleFileRemoved(const QString& path)
{
    handleFileUpdated(path, Deletion);
}

SharingObserver::Result SharingObserver::importContainerInto(const Sharing::Reference& reference, Group* targetGroup)
{
    const QFileInfo info(reference.path);
    QFile dbFile(info.absoluteFilePath());
    if (!info.exists()) {
        qCritical("File %s does not exist.", qPrintable(info.absoluteFilePath()));
        return {reference.path, Result::Warning, tr("File does not exist")};
    }
    QuaZip zip(info.absoluteFilePath());
    if (!zip.open(QuaZip::mdUnzip)) {
        qCritical("Unable to open file %s.", qPrintable(info.absoluteFilePath()));
        return {reference.path, Result::Error, tr("File is not readable")};
    }
    QSet<QString> expected = QSet<QString>() << KeeShareExt_Signature  << KeeShareExt_Container;
    const QList<QuaZipFileInfo> files = zip.getFileInfoList();
    QSet<QString> actual;
    for( const QuaZipFileInfo& file : files ){
        actual << file.name;
    }
    if( expected != actual ){
        qCritical("Invalid sharing container %s.", qPrintable(info.absoluteFilePath()));
        return {reference.path, Result::Error, tr("Invalid sharing container")};
    }

    zip.setCurrentFile(KeeShareExt_Signature);
    QuaZipFile signatureFile(&zip);
    signatureFile.open(QuaZipFile::ReadOnly);
    QString signature = signatureFile.readAll();
    signatureFile.close();

    zip.setCurrentFile(KeeShareExt_Container);
    QuaZipFile databaseFile(&zip);
    databaseFile.open(QuaZipFile::ReadOnly);
    QByteArray payload = databaseFile.readAll();
    databaseFile.close();
    QBuffer buffer(&payload);
    buffer.open(QIODevice::ReadOnly);

    KeePass2Reader reader;
    CompositeKey key;
    key.addKey(PasswordKey(reference.password));
    Database* sourceDb = reader.readDatabase(&buffer, key);
    if (reader.hasError()) {
        qCritical("Error while parsing the database: %s", qPrintable(reader.errorString()));
        return {reference.path, Result::Error, reader.errorString()};
    }
    Database *targetDb = targetGroup->database();
    auto trusted = Sharing::unsign(sourceDb, targetDb, payload, reference, signature);
    Sharing::Settings settings = Sharing::settingsOf(targetDb);
    switch( trusted.first ){
    case Sharing::None:
        qWarning("Prevent untrusted import");
        return {reference.path, Result::Warning, tr("Untrusted import prevented") };

    case Sharing::Invalid:
        qCritical("Prevent untrusted import");
        return {reference.path, Result::Error, tr("Untrusted import prevented") };

    case Sharing::Known:
        // intended fallthrough to update signer when needed
    case Sharing::Lasting: {
            Sharing::Settings copy = settings;
            bool found = false;
            for( Sharing::Certificate &knownCertificate : copy.foreignCertificates ){
                if( knownCertificate.key == trusted.second.key ){
                    knownCertificate.signer = trusted.second.signer;
                    knownCertificate.trusted = true;
                    found = true;
                }
            }
            if( ! found ){
                copy.foreignCertificates << trusted.second;
            }
            // we need to update with the new signer
            Sharing::setSettingsTo(targetDb, copy);
        }
        // intended fallthrough
    case Sharing::Single:
        // intended fallthrough
    case Sharing::Own: {
            qDebug("Synchronize %s %s with %s",
                   qPrintable(reference.path),
                   qPrintable(targetGroup->name()),
                   qPrintable(sourceDb->rootGroup()->name()));
            Merger merger(sourceDb->rootGroup(), targetGroup);
            merger.setForcedMergeMode(Group::Synchronize);
            const bool changed = merger.merge();
            if (changed) {
                return {reference.path, Result::Success, tr("Successful import")};
            }
            return {};
        }
    default:
        Q_ASSERT(false);
        return {};
    }
}

SharingObserver::Result SharingObserver::importFromReferenceContainer(const QString& path)
{
    if (!Sharing::isEnabled(m_db, Sharing::ImportFrom)) {
        return {};
    }
    QPointer<Group> shareGroup = m_shareToGroup.value(path);
    if (!shareGroup) {
        qWarning("Source for %s does not exist", qPrintable(path));
        Q_ASSERT(shareGroup);
        return {};
    }
    const Sharing::Reference reference = Sharing::referenceOf(shareGroup->customData());
    if (reference.type == Sharing::Inactive) {
        qDebug("Ignore change of inactive reference %s", qPrintable(reference.path));
        return {};
    }
    if (reference.type == Sharing::ExportTo) {
        qDebug("Ignore change of export reference %s", qPrintable(reference.path));
        return {};
    }
    Q_ASSERT(shareGroup->database() == m_db);
    Q_ASSERT(shareGroup == m_db->rootGroup()->findGroupByUuid(shareGroup->uuid()));
    return importContainerInto(reference, shareGroup);
}

void SharingObserver::resolveReferenceAttributes(Entry* targetEntry, const Database* sourceDb)
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

Database* SharingObserver::exportIntoContainer(const Sharing::Reference& reference, const Group* sourceRoot)
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
    Sharing::setReferenceTo(targetRoot->customData(), Sharing::Reference());
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
    Sharing::assignCertificate(targetDb, sourceDb);
    return targetDb;
}


const Database* SharingObserver::database() const
{
    return m_db;
}

Database* SharingObserver::database()
{
    return m_db;
}

void SharingObserver::handleDatabaseOpened()
{
    if (!m_db) {
        Q_ASSERT(m_db);
        return;
    }
    if (!Sharing::isEnabled(m_db, Sharing::ExportTo) && !Sharing::isEnabled(m_db, Sharing::ImportFrom)) {
        deinitialize();
    } else {
        reinitialize();
    }
}

QList<SharingObserver::Result> SharingObserver::exportIntoReferenceContainers()
{
    QList<Result> results;
    const Sharing::Settings sourceSettings = Sharing::settingsOf(m_db);
    const QList<Group*> groups = m_db->rootGroup()->groupsRecursive(true);
    for (const Group* group : groups) {
        const Sharing::Reference reference = Sharing::referenceOf(group->customData());
        if (!reference.isExporting()) {
            continue;
        }

        m_fileWatcher->ignoreFileChanges(reference.path);
        QScopedPointer<Database> targetDb(exportIntoContainer(reference, group));
        QByteArray bytes;
        {
            QBuffer buffer(&bytes);
            buffer.open(QIODevice::WriteOnly);
            KeePass2Writer writer;
            writer.writeDatabase(&buffer, targetDb.data());
            if (writer.hasError()) {
                qWarning("Serializing export dabase failed: %s.", writer.errorString().toLatin1().data());
                results << Result{reference.path, Result::Error, writer.errorString()};
                m_fileWatcher->observeFileChanges(true);
                continue;
            }
        }
        QuaZip zip(reference.path);
        zip.setFileNameCodec( "UTF-8" );
        const bool zipOpened = zip.open(QuaZip::mdCreate);
        if( !zipOpened ){
            ::qWarning("Opening export file failed: %d", zip.getZipError());
            results << Result{reference.path, Result::Error, tr("Could not write export container (%1)").arg(zip.getZipError()) };
            m_fileWatcher->observeFileChanges(true);
            continue;
        }
        {
            QuaZipFile file(&zip);
            const bool signatureOpened = file.open(QIODevice::WriteOnly, QuaZipNewInfo(KeeShareExt_Signature));
            if( !signatureOpened ){
                ::qWarning("Embedding signature failed: %d", zip.getZipError());
                results << Result{reference.path, Result::Error, tr("Could not embed signature (%1)").arg(file.getZipError()) };
                m_fileWatcher->observeFileChanges(true);
                continue;
            }
            file.write(Sharing::sign(bytes, m_db));
            if( file.getZipError() != ZIP_OK ){
                ::qWarning("Embedding signature failed: %d", zip.getZipError());
                results << Result{reference.path, Result::Error, tr("Could not embed signature (%1)").arg(file.getZipError()) };
                m_fileWatcher->observeFileChanges(true);
                continue;
            }
            file.close();
        }
        {
            QuaZipFile file(&zip);
            const bool dbOpened = file.open(QIODevice::WriteOnly, QuaZipNewInfo(KeeShareExt_Container));
            if( !dbOpened ){
                ::qWarning("Embedding database failed: %d", zip.getZipError());
                results << Result{reference.path, Result::Error, tr("Could not embed database (%1)").arg(file.getZipError()) };
                m_fileWatcher->observeFileChanges(true);
                continue;
            }
            if( file.getZipError() != ZIP_OK ){
                ::qWarning("Embedding database failed: %d", zip.getZipError());
                results << Result{reference.path, Result::Error, tr("Could not embed database (%1)").arg(file.getZipError()) };
                m_fileWatcher->observeFileChanges(true);
                continue;
            }
            file.write(bytes);
            file.close();
        }
        zip.close();

        m_fileWatcher->observeFileChanges(true);
        results << Result{reference.path};
    }
    return results;
}

void SharingObserver::handleDatabaseSaved()
{
    if (!Sharing::isEnabled(m_db, Sharing::ExportTo)) {
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


SharingObserver::Result::Result(const QString& path, SharingObserver::Result::Type type, const QString& message)
    : path(path)
    , type(type)
    , message(message)
{
}

bool SharingObserver::Result::isValid() const
{
    return !path.isEmpty() || !message.isEmpty() || !message.isEmpty() || !message.isEmpty();
}

bool SharingObserver::Result::isError() const
{
    return !message.isEmpty() && type == Error;
}

bool SharingObserver::Result::isInfo() const
{
    return !message.isEmpty() && type == Info;
}

bool SharingObserver::Result::isWarning() const
{
    return !message.isEmpty() && type == Warning;
}
