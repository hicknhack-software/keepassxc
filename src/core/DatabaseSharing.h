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

#include <QFileSystemWatcher>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QStringList>
#include <QTimer>

#include "core/Uuid.h"
#include "gui/MessageWidget.h"

class Entry;
class Group;
class CustomData;
class Database;

class DatabaseSharing : public QObject
{
    Q_OBJECT

public:
    static QString sharingIndicatorSuffix(const Group* group, const QString& text);
    static QPixmap sharingIndicatorBadge(const Group* group, QPixmap pixmap);
    static bool isShared(const Group* group);

    explicit DatabaseSharing(Database* db, QObject* parent = nullptr);

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

        Reference()
            : type(Type::Inactive)
            , uuid(Uuid::random())
        {
        }
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
    static void removeReferenceFrom(CustomData* customData);
    static QString referenceTypeLabel(const Reference& reference);

    void exportSharedEntries();
    static bool isEnabled(const Database* db);
    static bool isEnabled(const Database* db, Type sharing);
    static void enable(Database* db, Type sharing);

    QList<Group*> shares() const;

signals:
    void sharingChanged(QString, MessageWidget::MessageType);

public slots:
    void handleChanged();

private slots:
    void unblockAutoReload();
    void handleDirectoryChanged(const QString& path);
    void handleFileChanged(const QString& path);

private:
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

        Result(const QString& path = QString(), Type type = Success, const QString& message = QString())
            : path(path)
            , type(type)
            , message(message)
        {
        }

        bool isValid() const;
        bool isError() const;
        bool isWarning() const;
        bool isInfo() const;
    };

    static bool isExporting(const Database* database, const Group* group);
    static bool isImporting(const Database* database, const Group* group);
    static QString serializeReference(const DatabaseSharing::Reference& reference);
    static Reference deserializeReference(const QString& raw);
    static void resolveReferenceAttributes(Entry* targetEntry, Database* sourceDb);

    Result handleReferenceChanged(const QString& path);
    Result exportSharedFrom(Group* group);
    void deinitialize();
    void reinitialize();
    void notifyAbout(const QStringList& success, const QStringList& warning, const QStringList& error);

private:
    Database* const m_db;
    QMap<Reference, QPointer<Group>> m_referenceToGroup;
    QMap<QPointer<Group>, Reference> m_groupToReference;
    QMap<QString, QPointer<Group>> m_shareToGroup;

    // Handling of filesystem changes - it would better to create a central
    // observer handling the filesystem which just notifies any client for changes
    QMap<QString, QDateTime> m_blockedPaths;
    QFileSystemWatcher m_fileWatcher;
    QMap<QString, bool> m_watched;
    QMap<QString, QSet<QString>> m_sources;
    QTimer m_fileWatchTimer;
    QTimer m_fileWatchUnblockTimer; // needed for Import/Export-References
};

#endif // KEEPASSXC_DATABASESHARING_H
