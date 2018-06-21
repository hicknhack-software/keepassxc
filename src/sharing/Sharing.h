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

#ifndef KEEPASSXC_SHARING_H
#define KEEPASSXC_SHARING_H

#include <QMap>
#include <QObject>

#include "core/Uuid.h"
#include "gui/MessageWidget.h"

class CustomData;
class Group;
class Database;
class SharingObserver;

class Sharing : public QObject
{
    Q_OBJECT
public:
    enum Type
    {
        Inactive = 0,
        ImportFrom = 1 << 0,
        ExportTo = 1 << 1,
        SynchronizeWith = ImportFrom | ExportTo
    };

    struct Reference
    {
        Type type;
        Uuid uuid;
        QString path;
        QString password;

        Reference();
        bool isNull() const;
        bool isActive() const;
        bool isExporting() const;
        bool isImporting() const;
        bool operator<(const Reference& other) const;
        bool operator==(const Reference& other) const;

        static QString serialize(const Reference &reference);
        static Reference deserialize(const QString &raw);
    };

    struct Certificate
    {
        QString type;
        bool trusted;
        QString key;
        QString signer;

        Certificate() : trusted(false) {}

        bool isNull() const;

        static QString serialize(const Certificate &certificate);
        static Certificate deserialize(const QString &raw);
    };

    struct Key
    {
        QString type;
        QString key;

        bool isNull() const;

        static QString serialize(const Key &key);
        static Key deserialize(const QString &raw);
    };

    struct Settings
    {
        Type type;
        Key ownKey;
        Certificate ownCertificate;
        QList<Certificate> foreignCertificates;

        Settings() : type(Inactive) {}
        bool isNull() const;

        static QString serialize(const Settings &settings);
        static Settings deserialize(const QString &raw);
    };

    enum Trust {
        None,
        Invalid,
        Single,
        Lasting,
        Known,
        Own
    };

    static Sharing* instance();
    static void init(QObject* parent);

    static QString indicatorSuffix(const Group* group, const QString& text);
    static QPixmap indicatorBadge(const Group* group, QPixmap pixmap);

    static bool isShared(const Group* group);
    static bool isEnabled(const Database* db, Type sharing);
    static void enable(Database* db, Type sharing);

    static Settings settingsOf(const Database* database);
    static void setSettingsTo(Database *database, const Settings& settings);
    static Settings encryptionSettingsFor(const Database* db);

    static QString fingerprintOf(const Certificate &certificate);

    static Reference referenceOf(const CustomData* customData);
    static void setReferenceTo(CustomData* customData, const Reference& reference);
    static QString referenceTypeLabel(const Reference& reference);

    static QPair<Trust, Certificate> unsign(Database *sourceDb, const Database *targetDb, QByteArray &data, const Reference &reference, const QString &signature);
    static QByteArray sign(const QByteArray &data, Database *sourceDb);
    static void assignCertificate(Database *targetDb, const Database *sourceDb);
    void connectDatabase(Database *newDb, Database *oldDb);
    void handleDatabaseOpened(Database *db);
    void handleDatabaseSaved(Database *db);
signals:
    void sharingChanged(Database*, QString, MessageWidget::MessageType);

private slots:
    void emitSharingMessage(const QString&, MessageWidget::MessageType);
    void handleDatabaseDeleted(QObject *db);
    void handleObserverDeleted(QObject *observer);
private:
    static QScopedPointer<Sharing> m_instance;

    explicit Sharing(QObject *parent);

    QMap<QObject*, QPointer<SharingObserver>> m_observersByDatabase;
    QMap<QObject*, QPointer<Database>> m_databasesByObserver;
};

#endif // KEEPASSXC_SHARING_H
