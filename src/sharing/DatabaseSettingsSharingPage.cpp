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

#include "DatabaseSettingsSharingPage.h"

#include "core/Database.h"
#include "core/FilePath.h"
#include "core/Group.h"
#include "sharing/Sharing.h"
#include "sharing/DatabaseSettingsSharingWidget.h"

#include <QApplication>
#include <QMessageBox>

DatabaseSettingsSharingPage::DatabaseSettingsSharingPage(DatabaseSettingsWidget *settings)
{
    Q_UNUSED(settings);
}

QString DatabaseSettingsSharingPage::name()
{
    return QApplication::tr("Sharing");
}

QIcon DatabaseSettingsSharingPage::icon()
{
    return FilePath::instance()->icon("apps", "preferences-system-network-sharing");
}

QWidget *DatabaseSettingsSharingPage::createWidget()
{
    return new DatabaseSettingsSharingWidget();
}

void DatabaseSettingsSharingPage::loadSettings(QWidget *widget, Database *db)
{
    DatabaseSettingsSharingWidget* settingsWidget = reinterpret_cast<DatabaseSettingsSharingWidget*>(widget);
    settingsWidget->loadSettings(db);
}

bool DatabaseSettingsSharingPage::saveSettings(QWidget *widget)
{
    DatabaseSettingsSharingWidget* settingsWidget = reinterpret_cast<DatabaseSettingsSharingWidget*>(widget);
    return settingsWidget->saveSettings();
}

