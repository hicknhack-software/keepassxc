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

#ifndef KEEPASSXC_GROUPSHARINGWIDGET_H
#define KEEPASSXC_GROUPSHARINGWIDGET_H

#include <QPointer>
#include <QWidget>
#include <QStandardItemModel>

class Group;
class Database;

namespace Ui
{
    class GroupSharingWidget;
}

class GroupSharingWidget : public QWidget
{
    Q_OBJECT
public:
    explicit GroupSharingWidget(QWidget* parent = nullptr);
    ~GroupSharingWidget();

    void setGroup(Group *temporaryGroup, Database *database);

private:
    void showSharingState();

private slots:
    void update();
    void selectType();
    void selectPassword();
    void selectPath();
    void setPath(const QString& path);
    void setGeneratedPassword(const QString& password);
    void togglePasswordGeneratorButton(bool checked);

private:
    QScopedPointer<Ui::GroupSharingWidget> m_ui;
    QPointer<Group> m_temporaryGroup;
    QPointer<Database> m_database;
};

#endif // KEEPASSXC_GROUPSHARINGWIDGET_H
