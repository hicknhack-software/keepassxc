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

#include "Sharing.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/DatabaseIcons.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "gui/MessageBox.h"
#include "sharing/Signature.h"
#include "sharing/SharingObserver.h"
#include "sshagent/OpenSSHKey.h"

#include <QPainter>

namespace {

static const QString KeeShareExt_ExportEnabled("Export");
static const QString KeeShareExt_ImportEnabled("Import");
static const QString KeeShareExt("KeeShareXC");
static const QString KeeShareExt_Certificate("KeeShareXC_Certificate");
static const QChar KeeShareExt_referencePropertyDelimiter('|');

Sharing::Certificate packCertificate(const OpenSSHKey &key, bool verified, const QString &signer)
{
    Sharing::Certificate extracted;
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
Sharing::Key packKey(const OpenSSHKey &key)
{
    Sharing::Key extracted;
    extracted.type = "rsa";
    QStringList parts;
    for( const QByteArray& part : key.privateParts() ){
        parts << part.toHex();
    }
    extracted.key = parts.join("|").toLatin1().toBase64();
    return extracted;
}
OpenSSHKey unpackKey(const Sharing::Key &sign)
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

OpenSSHKey unpackCertificate(const Sharing::Certificate& certificate)
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
QScopedPointer<Sharing> Sharing::m_instance;

Sharing* Sharing::instance()
{
    if (!m_instance) {
        qFatal("Race condition: instance wanted before it was initialized, this is a bug.");
    }

    return m_instance.data();
}

void Sharing::init(QObject* parent)
{
    m_instance.reset(new Sharing(parent));
}

Sharing::Settings Sharing::encryptionSettingsFor(const Database *db)
{
    OpenSSHKey key = OpenSSHKey::generate(false);
    key.openKey(QString());
    Settings settings;
    settings.ownKey = packKey(key);
    QString name = db->metadata()->name();
    if( name.isEmpty() ){
        name = db->rootGroup()->name();
    }
    settings.ownCertificate = packCertificate(key, true, name);
    return settings;
}

QString Sharing::Certificate::serialize(const Sharing::Certificate &certificate)
{
    const QStringList data = QStringList()
            << certificate.type
            << certificate.signer
            << (certificate.trusted ? "trusted" : "trusted")
            << certificate.key;
    return data.join(KeeShareExt_referencePropertyDelimiter);
}

bool Sharing::Certificate::isNull() const
{
    return type.isEmpty() && !trusted && key.isEmpty() && signer.isEmpty();
}

Sharing::Certificate Sharing::Certificate::deserialize(const QString &raw)
{
    const QStringList data = raw.split(KeeShareExt_referencePropertyDelimiter);
    Certificate certificate;
    certificate.type = data.value(0);
    certificate.signer = data.value(1);
    certificate.trusted = data.value(2) == "trusted";
    certificate.key = data.value(3);
    return certificate;
}

bool Sharing::Key::isNull() const
{
    return type.isEmpty() && key.isEmpty();
}

QString Sharing::Key::serialize(const Sharing::Key &key)
{
    const QStringList data = QStringList()
            << key.type
            << key.key;
    return data.join(KeeShareExt_referencePropertyDelimiter).toLatin1();
}

Sharing::Key Sharing::Key::deserialize(const QString &raw)
{
    const QStringList data = raw.split(KeeShareExt_referencePropertyDelimiter);
    Sharing::Key key;
    key.type = data.value(0);
    key.key = data.value(1);
    return key;
}

bool Sharing::Settings::isNull() const
{
    return type == Inactive
            && ownKey.isNull()
            && ownCertificate.isNull()
            && foreignCertificates.isEmpty();
}

QString Sharing::Settings::serialize(const Sharing::Settings &settings)
{
    QStringList foreign;
    for( const Certificate &certificate : settings.foreignCertificates ){
        foreign << Certificate::serialize(certificate).toLatin1().toBase64();
    }
    const QStringList serialized = QStringList()
            << QString::number(static_cast<int>(settings.type))
            << Key::serialize(settings.ownKey).toLatin1().toBase64()
            << Certificate::serialize(settings.ownCertificate).toLatin1().toBase64()
            << foreign.join(KeeShareExt_referencePropertyDelimiter).toLatin1().toBase64();
    return serialized.join(KeeShareExt_referencePropertyDelimiter);
}

Sharing::Settings Sharing::Settings::deserialize(const QString &raw)
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
        settings.foreignCertificates << Certificate::deserialize(QByteArray::fromBase64(foreign.toLatin1()));
    }
    return settings;
}


Sharing::Reference::Reference()
    : type(Type::Inactive)
    , uuid(Uuid::random())
{
}

bool Sharing::Reference::isNull() const
{
    return type == Inactive && path.isEmpty() && password.isEmpty();
}

bool Sharing::Reference::isActive() const
{
    return type != Inactive && !path.isEmpty();
}

bool Sharing::Reference::isExporting() const
{
    return (type & ExportTo) != 0 && !path.isEmpty();
}

bool Sharing::Reference::isImporting() const
{
    return (type & ImportFrom) != 0 && !path.isEmpty();
}

bool Sharing::Reference::operator<(const Reference& other) const
{
    if (type != other.type) {
        return type < other.type;
    }
    return path < other.path;
}

bool Sharing::Reference::operator==(const Reference& other) const
{
    return path == other.path && uuid == other.uuid && password == other.password && type == other.type;
}

QString Sharing::Reference::serialize(const Reference &reference)
{
    const QStringList raw = QStringList()
            << QString::number(static_cast<int>(reference.type))
            << reference.uuid.toHex()
            << reference.path.toLatin1().toBase64()
            << reference.password.toLatin1().toBase64();
    return raw.join(KeeShareExt_referencePropertyDelimiter);
}

Sharing::Reference Sharing::Reference::deserialize(const QString &raw)
{
    Reference reference;

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


bool Sharing::isEnabled(const Database* db, Type type)
{
    const Settings settings = Sharing::settingsOf(db);
    return (settings.type & type) != 0;
}

bool Sharing::isShared(const Group* group)
{
    return group->customData()->contains(KeeShareExt);
}

QString Sharing::fingerprintOf(const Certificate &certificate)
{
    const OpenSSHKey key = unpackCertificate(certificate);
    return key.fingerprint();
}

Sharing::Reference Sharing::referenceOf(const CustomData* customData)
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

Sharing::Settings Sharing::settingsOf(const Database *database)
{
    Q_ASSERT(database);
    const auto* meta = database->metadata();
    const auto* customData = meta->customData();
    return Settings::deserialize(customData->value(KeeShareExt));
}

void Sharing::setReferenceTo(CustomData* customData, const Reference& reference)
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

void Sharing::setSettingsTo(Database *database, const Settings &settings)
{
    Q_ASSERT( database );
    auto* metadata = database->metadata();
    auto* customData = metadata->customData();
    customData->set(KeeShareExt, Settings::serialize(settings));
}

QPixmap Sharing::indicatorBadge(const Group* group, QPixmap pixmap)
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

QString Sharing::referenceTypeLabel(const Reference& reference)
{
    switch (reference.type) {
    case Sharing::Inactive:
        return tr("Disabled share");
    case Sharing::ImportFrom:
        return tr("Import from");
    case Sharing::ExportTo:
        return tr("Export to");
    case Sharing::SynchronizeWith:
        return tr("Synchronize with");
    }
    return "";
}

QPair<Sharing::Trust, Sharing::Certificate> Sharing::unsign(Database *sourceDb, const Database *targetDb, QByteArray &data, const Sharing::Reference &reference, const QString &signature)
{
    if( signature.isEmpty() ){
        auto result = MessageBox::question(nullptr,
                                           tr("Untrustworthy container without signature"),
                                           tr("Do you want to import from unsigned container %1")
                                               .arg(reference.path),
                                           QMessageBox::Yes | QMessageBox::No,
                                           QMessageBox::No);
        Trust trust = result == QMessageBox::Yes ? Single : None;
        return qMakePair( trust, Certificate() );
    }
    QVariantMap map = sourceDb->publicCustomData();
    Sharing::Certificate importedCertificate = Sharing::Certificate::deserialize(map[KeeShareExt_Certificate].toString());
    Sharing::Settings settings = Sharing::settingsOf(targetDb);
    OpenSSHKey key = unpackCertificate(importedCertificate);
    key.openKey(QString());
    Signature signer;
    const bool success = signer.verify(data, signature, key);
    if( ! success ) {
        const QFileInfo info(reference.path);
        qCritical("Invalid signature for sharing container %s.", qPrintable(info.absoluteFilePath()));
        return qMakePair( Invalid, Certificate() );
    }
    if( settings.ownCertificate.key == importedCertificate.key ){
        return qMakePair( Own, settings.ownCertificate );
    }
    for( const Sharing::Certificate &certificate : settings.foreignCertificates ){
        if( certificate.key == importedCertificate.key && certificate.trusted ){
            return qMakePair( Known, importedCertificate );
        }
    }
    auto result = MessageBox::question(nullptr,
                                       tr("Untrustworthy certificate for sharing container"),
                                       tr("Do you want to trust %1 signing with the fingerprint of %2")
                                           .arg(importedCertificate.signer)
                                           .arg(fingerprintOf(importedCertificate)),
                                       QMessageBox::Yes | QMessageBox::No,
                                       QMessageBox::No);

    if( result != QMessageBox::Yes ){
        qWarning("Prevented import due to untrusted certificate of %s", qPrintable(importedCertificate.signer));
        return qMakePair( None, importedCertificate );
    }
    return qMakePair( Lasting, importedCertificate );
}

QByteArray Sharing::sign(const QByteArray &data, Database *sourceDb)
{
    const Sharing::Settings sourceSettings = Sharing::settingsOf(sourceDb);
    OpenSSHKey key = unpackKey(sourceSettings.ownKey);
    key.openKey(QString());
    Signature signer;
    return signer.create(data, key).toLatin1();
}

void Sharing::assignCertificate(Database *targetDb, const Database *sourceDb)
{
    const Sharing::Settings sourceSettings = Sharing::settingsOf(sourceDb);
    QVariantMap map = targetDb->publicCustomData();
    map[KeeShareExt_Certificate] = Sharing::Certificate::serialize(sourceSettings.ownCertificate);
    targetDb->setPublicCustomData(map);
}

QString Sharing::indicatorSuffix(const Group* group, const QString& text)
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



void Sharing::enable(Database* db, Type sharing)
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
void Sharing::connectDatabase(Database *newDb, Database *oldDb)
{
    if( oldDb && m_observersByDatabase.contains(oldDb) ){
        QPointer<SharingObserver> observer = m_observersByDatabase.take(oldDb);
        if( observer ){
            delete observer;
        }
    }

    if( newDb && !m_observersByDatabase.contains(newDb) ){
        QPointer<SharingObserver> observer(new SharingObserver(newDb, newDb));
        m_observersByDatabase[newDb] = observer;
        connect(observer.data(), SIGNAL(sharingMessage(QString, MessageWidget::MessageType))
                ,this, SLOT(emitSharingMessage(QString, MessageWidget::MessageType)));
    }
}

void Sharing::handleDatabaseOpened(Database *db)
{
    QPointer<SharingObserver> observer = m_observersByDatabase.value(db);
    if( observer ){
        observer->handleDatabaseOpened();
    }
}

void Sharing::handleDatabaseSaved(Database *db)
{
    QPointer<SharingObserver> observer = m_observersByDatabase.value(db);
    if( observer ){
        observer->handleDatabaseSaved();
    }
}

void Sharing::emitSharingMessage(const QString &message, KMessageWidget::MessageType type)
{
    QObject *observer = sender();
    Database* db = m_databasesByObserver.value(observer);
    if( db ){
        emit sharingChanged(db, message, type);
    }
}

void Sharing::handleDatabaseDeleted(QObject *db)
{
    auto observer = m_observersByDatabase.take(db);
    if( observer ){
        m_databasesByObserver.remove(observer);
    }
}

void Sharing::handleObserverDeleted(QObject *observer)
{
    auto database = m_databasesByObserver.take(observer);
    if( database ){
        m_observersByDatabase.remove(database);
    }
}

Sharing::Sharing(QObject *parent)
    : QObject(parent)
{

}



