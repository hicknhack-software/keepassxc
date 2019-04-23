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
#include "PathLineEdit.h"
#include "ui_PathLineEdit.h"

#include "core/Config.h"
#include "gui/FileDialog.h"
#include "keeshare/KeeShare.h"

#include <QDir>
#include <QStandardPaths>

PathLineEdit::PathLineEdit(QWidget *parent)
    : QWidget(parent)
    , m_ui(new Ui::PathLineEdit)
{
    m_ui->setupUi(this);

    connect(m_ui->pathEdit, &QLineEdit::editingFinished, this, &PathLineEdit::handlePathEditingFinished);
    connect(m_ui->pathEdit, &QLineEdit::textEdited, this, &PathLineEdit::pathChanged);
    connect(m_ui->pathSelector, &QToolButton::clicked, this, &PathLineEdit::handlePathSelectorClicked);
}

PathLineEdit::~PathLineEdit()
{
}

void PathLineEdit::setPath(const QString &path)
{
    m_ui->pathEdit->setText(path);
}

void PathLineEdit::setPlaceholderPath(const QString &path)
{
    m_ui->pathEdit->setPlaceholderText(path);
}

void PathLineEdit::setDialogDefaultDirectoryConfigKey(const QString &path)
{
    m_dialogDirectoryConfigKey = path;
}

void PathLineEdit::setDialogTitle(const QString &title)
{
    m_dialogTitle = title;
}

void PathLineEdit::handlePathEditingFinished()
{
    emit pathChanged(m_ui->pathEdit->text());
}

void PathLineEdit::handlePathSelectorClicked()
{
    QString defaultDirPath = config()->get(m_dialogDirectoryConfigKey).toString();
    const bool dirExists = !defaultDirPath.isEmpty() && QDir(m_dialogDirectoryConfigKey).exists();
    if (!dirExists) {
        defaultDirPath = QStandardPaths::standardLocations(QStandardPaths::DocumentsLocation).first();
    }

    auto filename = m_ui->pathEdit->text();
    if (filename.isEmpty()) {
        filename = m_ui->pathEdit->placeholderText();
    }
    filename = fileDialog()->getExistingDirectory(this, m_dialogTitle, defaultDirPath);

    m_ui->pathEdit->setText(filename);

    config()->set(m_dialogDirectoryConfigKey, QFileInfo(filename).absolutePath());

    emit pathChanged(filename);
}
