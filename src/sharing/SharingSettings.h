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

#ifndef KEEPASSXC_SHARINGSETTINGS_H
#define KEEPASSXC_SHARINGSETTINGS_H

#include <QMap>
#include <QObject>

#include "core/Uuid.h"
#include "crypto/ssh/OpenSSHKey.h"
#include "gui/MessageWidget.h"

class CustomData;
class Group;
class Database;
class SharingObserver;
class QXmlStreamWriter;
class QXmlStreamReader;

class SharingSettings
{
public:
    enum Type
    {
        Inactive = 0,
        ImportFrom = 1 << 0,
        ExportTo = 1 << 1,
        SynchronizeWith = ImportFrom | ExportTo
    };

    struct Certificate
    {
        QByteArray key;
        QString signer;
        bool trusted;

        Certificate() : trusted(false) {}

        bool isNull() const;
        QString fingerprint() const;
        OpenSSHKey sshKey() const;

        static void serialize(QXmlStreamWriter &writer, const Certificate &certificate);
        static void serialize(QXmlStreamWriter &writer, const Certificate &certificate, const QString &element);
        static Certificate deserialize(QXmlStreamReader &reader);
        static Certificate deserialize(QXmlStreamReader &reader, const QString &element);
    };

    struct Key
    {
        QByteArray key;

        bool isNull() const;
        OpenSSHKey sshKey() const;

        static void serialize(QXmlStreamWriter &writer, const Key &key);
        static void serialize(QXmlStreamWriter &writer, const Key &key, const QString &element);
        static Key deserialize(QXmlStreamReader &reader);
        static Key deserialize(QXmlStreamReader &reader, const QString &element);
    };

    bool importing;
    bool exporting;
    Key ownKey;
    Certificate ownCertificate;
    QList<Certificate> foreignCertificates;

    SharingSettings();
    bool isNull() const;

    static QString serialize(const SharingSettings &settings);
    static SharingSettings deserialize(const QString &raw);


    static SharingSettings generateEncryptionSettingsFor(const Database *db);
};

#endif // KEEPASSXC_SHARING_H
