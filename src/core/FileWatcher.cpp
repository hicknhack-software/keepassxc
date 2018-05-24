/*
 *  Copyright (C) 2011 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include "FileWatcher.h"

FileWatcher::FileWatcher(QObject *parent)
    : QObject(parent)
{
    connect(&m_fileWatcher, SIGNAL(fileChanged(QString)), this, SLOT(onWatchedFileChanged()));
    connect(&m_fileWatchUnblockTimer, SIGNAL(timeout()), this, SLOT(unblockAutoReload()));
    connect(&m_fileWatchTimer, SIGNAL(timeout()), SIGNAL(fileChanged()));

    m_fileWatchTimer.setSingleShot(true);
    m_fileWatchUnblockTimer.setSingleShot(true);
    m_ignoreAutoReload = false;
}

void FileWatcher::restart()
{
    m_fileWatcher.addPath(m_filePath);
}

void FileWatcher::stop()
{
    m_fileWatcher.removePath(m_filePath);
}

void FileWatcher::start(const QString &filePath)
{
    if (!m_filePath.isEmpty()) {
        m_fileWatcher.removePath(m_filePath);
    }

    m_fileWatcher.addPath(filePath);
    m_filePath = filePath;
}

void FileWatcher::blockAutoReload(bool block)
{
    if (block) {
        m_ignoreAutoReload = true;
        m_fileWatchTimer.stop();
    } else {
        m_fileWatchUnblockTimer.start(500);
    }
}

void FileWatcher::unblockAutoReload()
{
    m_ignoreAutoReload = false;
    start(m_filePath);
}
void FileWatcher::onWatchedFileChanged()
{
    if (m_ignoreAutoReload) {
        return;
    }
    if (m_fileWatchTimer.isActive())
        return;

    m_fileWatchTimer.start(500);
}
