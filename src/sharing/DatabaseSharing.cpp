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

static const QString KeeShareExt_ExportEnabled("Export");
static const QString KeeShareExt_ImportEnabled("Import");
static const QString KeeShareExt("KeeShareXC");
static const QString KeeShareExt_Certificate("KeeShareXC_Certificate");
static const QString KeeShareExt_Signature("container.share.signature");
static const QString KeeShareExt_Container("container.share.kdbx");
static const QChar KeeShareExt_referencePropertyDelimiter('|');

DatabaseSharing::Certificate packCertificate(const OpenSSHKey &key, bool verified, const QString &signer)
{
    DatabaseSharing::Certificate extracted;
    extracted.type = "rsa";
    extracted.trusted = verified;
    extracted.signer = signer;
    QStringList parts;
    for( const QByteArray& part : key.publicParts() ){
        parts << part.toHex();
    }
    extracted.key = parts.join("|").toLatin1().toBase64();
    return extracted;
}
DatabaseSharing::Key packKey(const OpenSSHKey &key)
{
    DatabaseSharing::Key extracted;
    extracted.type = "rsa";
    QStringList parts;
    for( const QByteArray& part : key.privateParts() ){
        parts << part.toHex();
    }
    extracted.key = parts.join("|").toLatin1().toBase64();
    return extracted;
}
OpenSSHKey unpackKey(const DatabaseSharing::Key &sign)
{
    OpenSSHKey key;
    const QString serialized = QByteArray::fromBase64(sign.key.toLatin1());
    const QStringList privateParts = serialized.split(KeeShareExt_referencePropertyDelimiter);
    QList<QByteArray> privateData;
    for( int i = 0; i < privateParts.count(); ++i){
        privateData << QByteArray::fromHex(privateParts[i].toLatin1());
    }
    key.m_rawType = OpenSSHKey::TYPE_RSA_PRIVATE;
    key.setPrivateData(privateData);
    return key;
}

OpenSSHKey unpackCertificate(const DatabaseSharing::Certificate& certificate)
{
    OpenSSHKey key;
    const QString serialized = QString::fromLatin1(QByteArray::fromBase64(certificate.key.toLatin1()));
    const QStringList publicParts = serialized.split(KeeShareExt_referencePropertyDelimiter);
    QList<QByteArray> publicData;
    for( int i = 0; i < publicParts.count(); ++i ){
        publicData << QByteArray::fromHex(publicParts[i].toLatin1());
    }
    key.m_rawType = OpenSSHKey::TYPE_RSA_PUBLIC;
    key.setPublicData(publicData);
    return key;
}

}

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
    const Settings settings = DatabaseSharing::settingsOf(db);
    return (settings.type & type) != 0;
}

bool DatabaseSharing::isShared(const Group* group)
{
    return group->customData()->contains(KeeShareExt);
}

QString DatabaseSharing::fingerprintOf(const DatabaseSharing::Certificate &certificate)
{
    const OpenSSHKey key = unpackCertificate(certificate);
    return key.fingerprint();
}

DatabaseSharing::Reference DatabaseSharing::referenceOf(const CustomData* customData)
{
    static const Reference s_emptyReference;
    if (!customData->contains(KeeShareExt)) {
        return s_emptyReference;
    }
    Reference reference = Reference::deserialize(customData->value(KeeShareExt));
    if( reference.isNull() ){
        qWarning("Invalid sharing reference detected - sharing disabled");
        return s_emptyReference;
    }
    return reference;
}

DatabaseSharing::Settings DatabaseSharing::settingsOf(const Database *database)
{
    Q_ASSERT(database);
    const auto* meta = database->metadata();
    const auto* customData = meta->customData();
    return Settings::deserialize(customData->value(KeeShareExt));
}

void DatabaseSharing::setReferenceTo(CustomData* customData, const DatabaseSharing::Reference& reference)
{
    if (reference.isNull()) {
        customData->remove(KeeShareExt);
        return;
    }
    if (customData->contains(KeeShareExt)) {
        customData->set(KeeShareExt, Reference::serialize(reference));
    }
    customData->set(KeeShareExt, Reference::serialize(reference));
}

void DatabaseSharing::setSettingsTo(Database *database, const DatabaseSharing::Settings &settings)
{
    Q_ASSERT( database );
    auto* metadata = database->metadata();
    auto* customData = metadata->customData();
    customData->set(KeeShareExt, Settings::serialize(settings));
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

void DatabaseSharing::assignDefaultsTo(DatabaseSharing::Settings &settings, Database *db)
{
    OpenSSHKey key = OpenSSHKey::generate(false);
    key.openKey(QString());

    settings.ownKey = packKey(key);
    settings.ownCertificate = packCertificate(key, true, db->metadata()->name());
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

bool DatabaseSharing::unsign(Database* sourceDb, const Database  *targetDb, QByteArray &data, const Reference& reference, const QString &signature)
{
    if( signature.isEmpty() ){
        //auto result = MessageBox::question(nullptr,
        //                                   tr("Untrustworthy container without signature"),
        //                                   tr("Do you want to import from unsigned container %1")
        //                                       .arg(reference.path),
        //                                   QMessageBox::Yes | QMessageBox::No,
        //                                   QMessageBox::No);
        //return result == QMessageBox::Yes;
        return true;

    }
    QVariantMap map = sourceDb->publicCustomData();
    Certificate importedCertificate = Certificate::deserialize(map[KeeShareExt_Certificate].toString());
    Settings settings = DatabaseSharing::settingsOf(targetDb);
    OpenSSHKey key = unpackCertificate(importedCertificate);
    key.openKey(QString());
    Signature signer;
    const bool success = signer.verify(data, signature, key);
    if( ! success ) {
        const QFileInfo info(reference.path);
        qCritical("Invalid signature for sharing container %s.", qPrintable(info.absoluteFilePath()));
        return false;
    }
    if( settings.ownCertificate.key == importedCertificate.key ){
        return true;
    }
    for( const DatabaseSharing::Certificate &certificate : settings.foreignCertificates ){
        if( certificate.key == importedCertificate.key && certificate.trusted ){
            return true;
        }
    }
    //auto result = MessageBox::question(nullptr,
    //                                   tr("Untrustworthy certificate for sharing container"),
    //                                   tr("Do you want to trust %1 signing with the fingerprint of %2")
    //                                       .arg(importedCertificate.signer)
    //                                       .arg(fingerprintOf(importedCertificate)),
    //                                   QMessageBox::Yes | QMessageBox::No,
    //                                   QMessageBox::No);

    //if( result != QMessageBox::Yes ){
    //    qWarning("Prevented import due to untrusted certificate of %s", qPrintable(importedCertificate.signer));
    //    return false;
    //}
    return true;
}

DatabaseSharing::Result DatabaseSharing::importContainerInto(const Reference& reference, Group* targetGroup)
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
    bool trusted = unsign(sourceDb, targetDb, payload, reference, signature);
    Certificate certificate = Certificate::deserialize(sourceDb->publicCustomData()[KeeShareExt_Certificate].toString());
    Settings settings = DatabaseSharing::settingsOf(targetDb);
    if(settings.ownCertificate.key != certificate.key && !signature.isEmpty()){
        Settings copy = settings;
        bool found = false;
        for( Certificate &knownCertificate : copy.foreignCertificates ){
            if( knownCertificate.key == certificate.key ){
                knownCertificate.signer = certificate.signer;
                knownCertificate.trusted = trusted;
                found = true;
            }
        }
        if( ! found ){
            copy.foreignCertificates << certificate;
        }
        // we need to update with the new signer
        setSettingsTo(targetDb, copy);
    }
    if (!trusted) {
        qCritical("Prevent untrusted import");
        return {reference.path, Result::Error, tr("Untrusted import prevented") };
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
    const Settings sourceSettings = DatabaseSharing::settingsOf(sourceDb);
    QVariantMap map = targetDb->publicCustomData();
    map[KeeShareExt_Certificate] = Certificate::serialize(sourceSettings.ownCertificate);
    targetDb->setPublicCustomData(map);
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
    const Settings sourceSettings = DatabaseSharing::settingsOf(m_db);
    const QList<Group*> groups = m_db->rootGroup()->groupsRecursive(true);
    for (const Group* group : groups) {
        const Reference reference = referenceOf(group->customData());
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
            OpenSSHKey key = unpackKey(sourceSettings.ownKey);
            key.openKey(QString());
            Signature signer;
            QuaZipFile file(&zip);
            const bool signatureOpened = file.open(QIODevice::WriteOnly, QuaZipNewInfo(KeeShareExt_Signature));
            if( !signatureOpened ){
                ::qWarning("Embedding signature failed: %d", zip.getZipError());
                results << Result{reference.path, Result::Error, tr("Could not embed signature (%1)").arg(file.getZipError()) };
                m_fileWatcher->observeFileChanges(true);
                continue;
            }
            file.write(signer.create(bytes, key).toLatin1());
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

QString DatabaseSharing::Reference::serialize(const Reference &reference)
{
    const QStringList raw = QStringList()
            << QString::number(static_cast<int>(reference.type))
            << reference.uuid.toHex()
            << reference.path.toLatin1().toBase64()
            << reference.password.toLatin1().toBase64();
    return raw.join(KeeShareExt_referencePropertyDelimiter);
}

DatabaseSharing::Reference DatabaseSharing::Reference::deserialize(const QString &raw)
{
    DatabaseSharing::Reference reference;

    const auto parts = raw.split(KeeShareExt_referencePropertyDelimiter);
    if (parts.count() != 4) {
        return reference;
    }
    reference.type = static_cast<Type>(parts[0].toInt());
    reference.uuid = Uuid::fromHex(parts[1]);
    reference.path = QByteArray::fromBase64(parts[2].toLatin1());
    reference.password = QByteArray::fromBase64(parts[3].toLatin1());

    return reference;
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

bool DatabaseSharing::Certificate::isNull() const
{
    return type.isEmpty() && !trusted && key.isEmpty() && signer.isEmpty();
}

QString DatabaseSharing::Certificate::serialize(const DatabaseSharing::Certificate &certificate)
{
    const QStringList data = QStringList()
            << certificate.type
            << certificate.signer
            << (certificate.trusted ? "trusted" : "trusted")
            << certificate.key;
    return data.join(KeeShareExt_referencePropertyDelimiter);
}

DatabaseSharing::Certificate DatabaseSharing::Certificate::deserialize(const QString &raw)
{
    const QStringList data = raw.split(KeeShareExt_referencePropertyDelimiter);
    DatabaseSharing::Certificate certificate;
    certificate.type = data.value(0);
    certificate.signer = data.value(1);
    certificate.trusted = data.value(2) == "trusted";
    certificate.key = data.value(3);
    return certificate;
}

bool DatabaseSharing::Key::isNull() const
{
    return type.isEmpty() && key.isEmpty();
}

QString DatabaseSharing::Key::serialize(const DatabaseSharing::Key &key)
{
    const QStringList data = QStringList()
            << key.type
            << key.key;
    return data.join(KeeShareExt_referencePropertyDelimiter).toLatin1();
}

DatabaseSharing::Key DatabaseSharing::Key::deserialize(const QString &raw)
{
    const QStringList data = raw.split(KeeShareExt_referencePropertyDelimiter);
    DatabaseSharing::Key key;
    key.type = data.value(0);
    key.key = data.value(1);
    return key;
}

bool DatabaseSharing::Settings::isNull() const
{
    return type == Inactive
            && ownKey.isNull()
            && ownCertificate.isNull()
            && foreignCertificates.isEmpty();
}

QString DatabaseSharing::Settings::serialize(const DatabaseSharing::Settings &settings)
{
    QStringList foreign;
    for( const DatabaseSharing::Certificate &certificate : settings.foreignCertificates ){
        foreign << DatabaseSharing::Certificate::serialize(certificate).toLatin1().toBase64();
    }
    const QStringList serialized = QStringList()
            << QString::number(static_cast<int>(settings.type))
            << Key::serialize(settings.ownKey).toLatin1().toBase64()
            << Certificate::serialize(settings.ownCertificate).toLatin1().toBase64()
            << foreign.join(KeeShareExt_referencePropertyDelimiter).toLatin1().toBase64();
    return serialized.join(KeeShareExt_referencePropertyDelimiter);
}

DatabaseSharing::Settings DatabaseSharing::Settings::deserialize(const QString &raw)
{
    Settings settings;
    const auto parts = raw.split(KeeShareExt_referencePropertyDelimiter);
    if (parts.count() != 4) {
        return settings;
    }
    settings.type = static_cast<Type>(parts[0].toInt());
    settings.ownKey = Key::deserialize(QByteArray::fromBase64(parts[1].toLatin1()));
    settings.ownCertificate = Certificate::deserialize(QByteArray::fromBase64(parts[2].toLatin1()));
    for( const QString &foreign : QString::fromLatin1(QByteArray::fromBase64(parts[3].toLatin1())).split(KeeShareExt_referencePropertyDelimiter, QString::SkipEmptyParts) ){
        settings.foreignCertificates << DatabaseSharing::Certificate::deserialize(QByteArray::fromBase64(foreign.toLatin1()));
    }
    return settings;
}
