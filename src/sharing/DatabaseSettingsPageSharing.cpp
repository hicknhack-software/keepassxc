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

#include "DatabaseSettingsPageSharing.h"

#include "core/Database.h"
#include "core/FilePath.h"
#include "core/Group.h"
#include "sharing/Sharing.h"
#include "sharing/DatabaseSettingsWidgetSharing.h"

#include <QApplication>

QString DatabaseSettingsPageSharing::name()
{
    return QApplication::tr("Sharing");
}

QIcon DatabaseSettingsPageSharing::icon()
{
    return FilePath::instance()->icon("apps", "preferences-system-network-sharing");
}

QWidget *DatabaseSettingsPageSharing::createWidget()
{
    return new DatabaseSettingsWidgetSharing();
}

void DatabaseSettingsPageSharing::loadSettings(QWidget *widget, Database *db)
{
    DatabaseSettingsWidgetSharing* settingsWidget = reinterpret_cast<DatabaseSettingsWidgetSharing*>(widget);
    settingsWidget->loadSettings(db);
}

bool DatabaseSettingsPageSharing::saveSettings(QWidget *widget)
{
    DatabaseSettingsWidgetSharing* settingsWidget = reinterpret_cast<DatabaseSettingsWidgetSharing*>(widget);
    return settingsWidget->saveSettings();
}

