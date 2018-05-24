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

#ifndef KEEPASSXC_FILEWATCHER_H
#define KEEPASSXC_FILEWATCHER_H

#include <QVariant>
#include <QTimer>
#include <QFileSystemWatcher>

class FileWatcher : public QObject
{
    Q_OBJECT

public:
    explicit FileWatcher(QObject *parent = nullptr);

    void blockAutoReload(bool block);
    void start(const QString &path);

    void restart();
    void stop();
signals:
    void fileChanged();

private slots:
    void unblockAutoReload();
    void onWatchedFileChanged();

private:
    QString m_filePath;
    QFileSystemWatcher m_fileWatcher;
    QTimer m_fileWatchTimer;
    QTimer m_fileWatchUnblockTimer;
    bool m_ignoreAutoReload;
};

#endif // KEEPASSXC_FILEWATCHER_H
