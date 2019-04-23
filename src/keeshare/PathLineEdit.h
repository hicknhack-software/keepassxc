/*
 *  Copyright (C) 2019 KeePassXC Team <team@keepassxc.org>
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
#ifndef KEEPASSXC_PATHLINEEDIT_H
#define KEEPASSXC_PATHLINEEDIT_H

#include <QWidget>

namespace Ui {
class PathLineEdit;
}

class PathLineEdit : public QWidget
{
    Q_OBJECT

public:
    explicit PathLineEdit(QWidget *parent = nullptr);
    ~PathLineEdit();

//    enum DialogType {
//        DialogTypeSelect,
//        DialogTypeOverwrite
//    };

    void setPath(const QString &path);
    void setPlaceholderPath(const QString &path);
    // void setDialogDefaultPath(const QString &path){}
    void setDialogDefaultDirectoryConfigKey(const QString &path);
    void setDialogTitle(const QString &title);

signals:
    void pathChanged(const QString &text);

private slots:
    void handlePathSelectorClicked();
    void handlePathEditingFinished();
private:
    QScopedPointer<Ui::PathLineEdit> m_ui;

    QString m_dialogDirectoryConfigKey;
    QString m_dialogTitle;
};

#endif // KEEPASSXC_PATHLINEEDIT_H
