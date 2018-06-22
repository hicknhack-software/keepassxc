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

#ifndef KEEPASSXC_DATABASESETTINGSSHARINGWIDGET_H
#define KEEPASSXC_DATABASESETTINGSSHARINGWIDGET_H

#include <QScopedPointer>
#include <QPointer>
#include <QWidget>

class Database;

class QStandardItemModel;

namespace Ui
{
    class DatabaseSettingsSharingWidget;
}

class DatabaseSettingsSharingWidget : public QWidget
{
    Q_OBJECT
public:
    explicit DatabaseSettingsSharingWidget(QWidget* parent = nullptr);
    ~DatabaseSettingsSharingWidget();

    void loadSettings(Database *db);
    bool saveSettings();

private slots:
    void setVerificationExporter(const QString &signer);
    void generateCerticate();
    void clearCerticate();

private:
    QScopedPointer<Ui::DatabaseSettingsSharingWidget> m_ui;

    QString m_sharingInformation;
    QScopedPointer<QStandardItemModel> m_referencesModel;
    QScopedPointer<QStandardItemModel> m_verificationModel;
    QPointer<Database> m_db;
};

#endif // KEEPASSXC_DATABASESETTINGSSHARINGWIDGET_H
