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

#include "SharingSettings.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/DatabaseIcons.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "crypto/ssh/OpenSSHKey.h"
#include "sharing/Signature.h"
#include "sharing/SharingObserver.h"

#include <QPainter>
#include <QPushButton>
#include <QMessageBox>

namespace {

static const QString KeeShareExt("KeeShare");

SharingSettings::Certificate packCertificate(const OpenSSHKey &key, bool verified, const QString &signer)
{
    SharingSettings::Certificate extracted;
    extracted.trusted = verified;
    extracted.signer = signer;
    Q_ASSERT(key.type() == "ssh-rsa");
    extracted.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Public, key);
    return extracted;
}

SharingSettings::Key packKey(const OpenSSHKey &key)
{
    SharingSettings::Key extracted;
    Q_ASSERT(key.type() == "ssh-rsa");
    extracted.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Private, key);
    return extracted;
}

OpenSSHKey unpackKey(const SharingSettings::Key &sign)
{
    if(sign.key.isEmpty()){
        return OpenSSHKey();
    }
    OpenSSHKey key = OpenSSHKey::restoreFromBinary(OpenSSHKey::Private, sign.key);
    Q_ASSERT(key.type() == "ssh-rsa");
    return key;
}

OpenSSHKey unpackCertificate(const SharingSettings::Certificate& certificate)
{
    if(certificate.key.isEmpty()){
        return OpenSSHKey();
    }
    OpenSSHKey key = OpenSSHKey::restoreFromBinary(OpenSSHKey::Public, certificate.key);
    Q_ASSERT(key.type() == "ssh-rsa");
    return key;
}
}

void SharingSettings::Certificate::serialize(QXmlStreamWriter &writer, const SharingSettings::Certificate &certificate)
{
    if( certificate.isNull() ){
        return;
    }
    writer.writeStartElement("Signer");
    writer.writeCharacters(certificate.signer);
    writer.writeEndElement();
    writer.writeStartElement("Trusted");
    writer.writeCharacters(certificate.trusted ? "True" : "False");
    writer.writeEndElement();
    writer.writeStartElement("Key");
    writer.writeCharacters(certificate.key.toBase64());
    writer.writeEndElement();
}

void SharingSettings::Certificate::serialize(QXmlStreamWriter &writer, const SharingSettings::Certificate &certificate, const QString &element)
{
    writer.writeStartElement(element);
    serialize(writer, certificate);
    writer.writeEndElement();
}

bool SharingSettings::Certificate::isNull() const
{
    return !trusted && key.isEmpty() && signer.isEmpty();
}

QString SharingSettings::Certificate::fingerprint() const
{
    if( isNull() ){
        return "";
    }
    const OpenSSHKey key = unpackCertificate(*this);
    return key.fingerprint();
}

OpenSSHKey SharingSettings::Certificate::sshKey() const
{
    return unpackCertificate(*this);
}

SharingSettings::Certificate SharingSettings::Certificate::deserialize(QXmlStreamReader &reader)
{
    Certificate certificate;
    while( !reader.error() && reader.readNextStartElement()){
        if( reader.name() == "Signer" ){
            certificate.signer = reader.readElementText();
        } else if( reader.name() == "Trusted" ){
            certificate.trusted = reader.readElementText() == "True";
        } else if( reader.name() == "Key" ){
            certificate.key = QByteArray::fromBase64(reader.readElementText().toLatin1());
        }
    }
    return certificate;
}

SharingSettings::Certificate SharingSettings::Certificate::deserialize(QXmlStreamReader &reader, const QString &element)
{
    reader.readNextStartElement();
    if( reader.error() || reader.name() != element){
        return Certificate();
    }
    return deserialize(reader);
}

bool SharingSettings::Key::isNull() const
{
    return key.isEmpty();
}

OpenSSHKey SharingSettings::Key::sshKey() const
{
    return unpackKey(*this);
}

void SharingSettings::Key::serialize(QXmlStreamWriter &writer, const SharingSettings::Key &key)
{
    if( key.isNull() ){
        return;
    }
    writer.writeCharacters(key.key.toBase64());
}

void SharingSettings::Key::serialize(QXmlStreamWriter &writer, const SharingSettings::Key &key, const QString &element)
{
    writer.writeStartElement(element);
    serialize(writer, key);
    writer.writeEndElement();
}

SharingSettings::Key SharingSettings::Key::deserialize(QXmlStreamReader &reader)
{
    Key key;
    key.key = QByteArray::fromBase64(reader.readElementText().toLatin1());
    return key;
}

SharingSettings::Key SharingSettings::Key::deserialize(QXmlStreamReader &reader, const QString &element)
{
    reader.readNextStartElement();
    if( reader.error() || reader.name() != element){
        return Key();
    }
    return deserialize(reader);
}

SharingSettings::SharingSettings()
    : importing(false)
    , exporting(false)
{
}

bool SharingSettings::isNull() const
{
    return importing == false
            && exporting == false
            && ownKey.isNull()
            && ownCertificate.isNull()
            && foreignCertificates.isEmpty();
}

QString SharingSettings::serialize(const SharingSettings &settings)
{
    QString buffer;
    QXmlStreamWriter writer(&buffer);

    writer.setCodec(QTextCodec::codecForName("UTF-8"));
    writer.setAutoFormatting(true);
    writer.setAutoFormattingIndent(2);

    writer.writeStartDocument();
    writer.writeStartElement("SharingSettings");
    writer.writeAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
    writer.writeAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
    writer.writeStartElement("Type");
    if( settings.importing ) {
        writer.writeEmptyElement("Import");
    }
    if( settings.exporting ) {
        writer.writeEmptyElement("Export");
    }
    writer.writeEndElement();
    writer.writeStartElement("PrivateKey");
    Key::serialize(writer, settings.ownKey);
    writer.writeEndElement();
    writer.writeStartElement("PublicKey");
    Certificate::serialize(writer, settings.ownCertificate);
    writer.writeEndElement();

    writer.writeStartElement("Certificates");
    for( const Certificate &certificate : settings.foreignCertificates ){
        Certificate::serialize(writer, certificate, "Certificate");
    }
    writer.writeEndElement();
    writer.writeEndElement();
    writer.writeEndDocument();
    return buffer;
}

SharingSettings SharingSettings::deserialize(const QString &raw)
{
    SharingSettings settings;
    QXmlStreamReader reader(raw);
    if( !reader.readNextStartElement() || reader.qualifiedName() != "SharingSettings" ){
        return settings;
    }
    while( !reader.error() && reader.readNextStartElement() ){
        if( reader.name() == "Type" ){
            while( reader.readNextStartElement() ){
                if( reader.name() == "Import" ){
                    settings.importing = true;
                    reader.skipCurrentElement();
                } else if( reader.name() == "Export" ){
                    settings.exporting = true;
                    reader.skipCurrentElement();
                } else {
                    break;
                }
            }
        } else if( reader.name() == "PrivateKey" ){
            settings.ownKey = Key::deserialize(reader);
        } else if( reader.name() == "PublicKey" ){
            settings.ownCertificate = Certificate::deserialize(reader);
        } else if( reader.name() == "Certificates") {
            while( !reader.error() && reader.readNextStartElement() ){
                if( reader.name() == "Certificate" ){
                    settings.foreignCertificates << Certificate::deserialize(reader);
                }
                else {
                    ::qWarning() << "Unknown Cerificates element" << reader.name();
                    reader.skipCurrentElement();
                }
            }
        } else {
            ::qWarning() << "Unknown SharingSettings element" << reader.name();
            reader.skipCurrentElement();
        }
    }
    return settings;
}

SharingSettings SharingSettings::generateEncryptionSettingsFor(const Database *db)
{
    OpenSSHKey key = OpenSSHKey::generate(false);
    key.openKey(QString());
    SharingSettings settings;
    settings.ownKey = packKey(key);
    QString name = db->metadata()->name();
    if( name.isEmpty() ){
        name = db->rootGroup()->name();
    }
    settings.ownCertificate = packCertificate(key, true, name);
    return settings;
}


