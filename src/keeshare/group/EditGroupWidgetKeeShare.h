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

#ifndef KEEPASSXC_EDITGROUPWIDGETKEESHARE_H
#define KEEPASSXC_EDITGROUPWIDGETKEESHARE_H

#include <QFormLayout>
#include <QLabel>
#include <QPointer>
#include <QStandardItemModel>
#include <QWidget>

#include <QStyledItemDelegate>

class Group;
class Database;
class PathLineEdit;

namespace Ui
{
    class EditGroupWidgetKeeShare;
}

class EditGroupWidgetKeeShare : public QWidget
{
    Q_OBJECT
public:
    explicit EditGroupWidgetKeeShare(QWidget* parent = nullptr);
    ~EditGroupWidgetKeeShare();

    void setGroup(Group* temporaryGroup, QSharedPointer<Database> database);

private:
    void reset();
    void reinitialize();
    void addOverrides(QFormLayout* layout, const QSet<QString>& keys);
    void removeOverrides(QFormLayout* layout, const QSet<QString>& keys);

private slots:
    void update();
    void clearInputs();
    void selectType();
    void selectPassword();
    void selectPath();
    void setGeneratedPassword(const QString& password);
    void togglePasswordGeneratorButton(bool checked);
    void showSharingState();

private:
    QScopedPointer<Ui::EditGroupWidgetKeeShare> m_ui;
    QPointer<Group> m_temporaryGroup;
    QSharedPointer<Database> m_database;
    QMap<QString, QLabel*> m_overrideLabels;
    QMap<QString, PathLineEdit*> m_overridePathEdits;
};

#endif // KEEPASSXC_EDITGROUPWIDGETKEESHARE_H
