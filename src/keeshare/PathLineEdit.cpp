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

PathLineEdit::PathLineEdit(QWidget* parent)
    : QWidget(parent)
    , m_ui(new Ui::PathLineEdit)
    , m_type(SelectInputOnly)
{
    m_ui->setupUi(this);

    connect(m_ui->pathEdit, &QLineEdit::editingFinished, this, &PathLineEdit::handlePathEditingFinished);
    connect(m_ui->pathEdit, &QLineEdit::textEdited, this, &PathLineEdit::pathChanged);
    connect(m_ui->pathSelector, &QToolButton::clicked, this, &PathLineEdit::handlePathSelectorClicked);
}

PathLineEdit::~PathLineEdit()
{
}

void PathLineEdit::clear()
{
    m_ui->pathEdit->clear();
}

void PathLineEdit::setType(PathLineEdit::Type type)
{
    m_type = type;

    m_ui->pathSelector->setVisible(m_type != SelectInputOnly);
}

void PathLineEdit::setPath(const QString& path)
{
    m_ui->pathEdit->setText(path);
}

void PathLineEdit::setPlaceholderPath(const QString& path)
{
    m_ui->pathEdit->setPlaceholderText(path);
}

void PathLineEdit::setDialogDefaultDirectoryConfigKey(const QString& path)
{
    m_dialogDirectoryConfigKey = path;
}

void PathLineEdit::setDialogTitle(const QString& title)
{
    m_dialogTitle = title;
}

void PathLineEdit::setDialogSupportedExtensions(const QList<QPair<QString, QString>>& extensionWithName,
                                                const QString& fallbackExtension)
{
    m_dialogFallbackExtension = fallbackExtension;
    m_dialogSupportedExtensionWithName = extensionWithName;
}

void PathLineEdit::setDialogUnsupportedExtensions(const QList<QString>& filters)
{
    m_dialogUnsupportedExtension = filters;
}

QString PathLineEdit::path() const
{
    return m_ui->pathEdit->text();
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

    auto supportedExtensions = QStringList();
    auto filters = QStringList();
    for (auto it = m_dialogSupportedExtensionWithName.cbegin(); it != m_dialogSupportedExtensionWithName.cend(); ++it) {
        if (!it->first.isEmpty()) {
            filters << QString("%1 (*.%2)").arg(it->second, it->first);
            supportedExtensions << it->first;
        } else {
            filters << QString("%1 (*)").arg(it->second, it->first);
        }
    }
    auto unsupportedExtensions = m_dialogUnsupportedExtension;

    switch (m_type) {
    case SelectDirectory:
        filename = fileDialog()->getExistingDirectory(this, m_dialogTitle, defaultDirPath);
        break;
    case SelectReadFile:
        filename = fileDialog()->getFileName(this,
                                             m_dialogTitle,
                                             defaultDirPath,
                                             filters.join(";;"),
                                             nullptr,
                                             QFileDialog::DontConfirmOverwrite,
                                             m_dialogFallbackExtension,
                                             filename);
        break;
    case SelectWriteFile:
        filename = fileDialog()->getFileName(this,
                                             m_dialogTitle,
                                             defaultDirPath,
                                             filters.join(";;"),
                                             nullptr,
                                             QFileDialog::Option(0),
                                             m_dialogFallbackExtension,
                                             filename);
        break;
    default:
        Q_ASSERT(false);
        return;
    }

    if (m_type != SelectDirectory) {
        bool validFilename = false;
        for (const auto& extension : supportedExtensions + unsupportedExtensions) {
            if (filename.endsWith(extension, Qt::CaseInsensitive)) {
                validFilename = true;
                break;
            }
        }
        if (!validFilename && !m_dialogFallbackExtension.isEmpty()) {
            filename += (!filename.endsWith(".") ? "." : "") + m_dialogFallbackExtension;
        }
    }

    m_ui->pathEdit->setText(filename);

    config()->set(m_dialogDirectoryConfigKey, QFileInfo(filename).absolutePath());

    emit pathChanged(filename);
}
