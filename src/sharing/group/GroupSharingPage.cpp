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

#include "GroupSharingPage.h"

#include "core/FilePath.h"
#include "sharing/group/GroupSharingWidget.h"

#include <QApplication>

GroupSharingPage::GroupSharingPage(EditGroupWidget *widget)
{
    Q_UNUSED(widget);
}

QString GroupSharingPage::name()
{
    return QApplication::tr("Sharing");
}

QIcon GroupSharingPage::icon()
{
    return FilePath::instance()->icon("apps", "preferences-system-network-sharing");
}

QWidget *GroupSharingPage::createWidget()
{
    return new GroupSharingWidget();
}

void GroupSharingPage::set(QWidget *widget, Group *temporaryGroup, Database *database)
{
    GroupSharingWidget *settingsWidget = reinterpret_cast<GroupSharingWidget*>(widget);
    settingsWidget->setGroup(temporaryGroup, database);
}

void GroupSharingPage::assign(QWidget *widget)
{
    Q_UNUSED(widget);
    // everything is saved directly
}

