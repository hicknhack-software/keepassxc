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

#ifndef KEEPASSXC_DATABASESHARING_H
#define KEEPASSXC_DATABASESHARING_H

#include <QMap>
#include <QObject>
#include <QSet>
#include <QStringList>
#include <QTimer>

#include "core/Uuid.h"
#include "gui/MessageWidget.h"

class BulkFileWatcher;
class Entry;
class Group;
class CustomData;
class Database;

class DatabaseSharing : public QObject
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
        Reference(Type type, const Uuid& uuid, const QString& path, const QString& password);
        bool isNull() const;
        bool isActive() const;
        bool isExporting() const;
        bool isImporting() const;
        bool operator<(const Reference& other) const;
        bool operator==(const Reference& other) const;
    };

    static Reference referenceOf(const CustomData* customData);
    static void setReferenceTo(CustomData* customData, const Reference& reference);
    static QString referenceTypeLabel(const Reference& reference);

    static QString indicatorSuffix(const Group* group, const QString& text);
    static QPixmap indicatorBadge(const Group* group, QPixmap pixmap);
    static bool isShared(const Group* group);
    static bool isEnabled(const Database* db, Type sharing);
    static void enable(Database* db, Type sharing);

    explicit DatabaseSharing(Database* db, QObject* parent = nullptr);
    ~DatabaseSharing();

    void handleDatabaseSaved();
    void handleDatabaseOpened();

    const Database* database() const;
    Database* database();

signals:
    void sharingChanged(QString, MessageWidget::MessageType);

public slots:
    void handleDatabaseChanged();

private slots:
    void handleFileCreated(const QString& path);
    void handleFileChanged(const QString& path);
    void handleFileRemoved(const QString& path);

private:
    enum Change
    {
        Creation,
        Update,
        Deletion
    };

    struct Result
    {
        enum Type
        {
            Success,
            Info,
            Warning,
            Error
        };

        QString path;
        Type type;
        QString message;

        Result(const QString& path = QString(), Type type = Success, const QString& message = QString());

        bool isValid() const;
        bool isError() const;
        bool isWarning() const;
        bool isInfo() const;
    };

    static QString serializeReference(const DatabaseSharing::Reference& reference);
    static Reference deserializeReference(const QString& raw);
    static void resolveReferenceAttributes(Entry* targetEntry, const Database* sourceDb);

    static Database* exportIntoContainer(const Reference& reference, const Group* sourceRoot);
    static Result importContainerInto(const Reference& reference, Group* targetGroup);

    static void createSignature(Database *db);

    Result importFromReferenceContainer(const QString& path);
    QList<DatabaseSharing::Result> exportIntoReferenceContainers();
    void deinitialize();
    void reinitialize();

    void handleFileUpdated(const QString& path, Change change);
    void notifyAbout(const QStringList& success, const QStringList& warning, const QStringList& error);

private:
    Database* const m_db;
    QMap<Reference, QPointer<Group>> m_referenceToGroup;
    QMap<QPointer<Group>, Reference> m_groupToReference;
    QMap<QString, QPointer<Group>> m_shareToGroup;

    BulkFileWatcher* m_fileWatcher;
};

#endif // KEEPASSXC_DATABASESHARING_H
