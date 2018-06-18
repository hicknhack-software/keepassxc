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

#include "GroupSharingWidget.h"
#include "ui_GroupSharingWidget.h"

#include "core/Config.h"
#include "core/CustomData.h"
#include "core/FilePath.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "gui/FileDialog.h"
#include "sharing/DatabaseSharing.h"
#include "sshagent/OpenSSHKey.h"

#include <QDir>
#include <QStandardPaths>

GroupSharingWidget::GroupSharingWidget(QWidget* parent)
    : QWidget(parent)
    , m_ui(new Ui::GroupSharingWidget())
{
    m_ui->setupUi(this);

    m_ui->togglePasswordButton->setIcon(filePath()->onOffIcon("actions", "password-show"));
    m_ui->togglePasswordGeneratorButton->setIcon(filePath()->icon("actions", "password-generator", false));

    m_ui->passwordGenerator->layout()->setContentsMargins(0, 0, 0, 0);
    m_ui->passwordGenerator->hide();
    m_ui->passwordGenerator->reset();

    m_ui->messageWidget->hide();

    connect(m_ui->togglePasswordButton, SIGNAL(toggled(bool)), m_ui->passwordEdit, SLOT(setShowPassword(bool)));
    connect(m_ui->togglePasswordGeneratorButton, SIGNAL(toggled(bool)), SLOT(togglePasswordGeneratorButton(bool)));
    connect(m_ui->passwordEdit, SIGNAL(textChanged(QString)), SLOT(selectPassword()));
    connect(m_ui->passwordGenerator, SIGNAL(appliedPassword(QString)), SLOT(setGeneratedPassword(QString)));
    connect(m_ui->pathEdit, SIGNAL(textChanged(QString)), SLOT(setPath(QString)));
    connect(m_ui->pathSelectionButton, SIGNAL(pressed()), SLOT(selectPath()));
    connect(m_ui->typeComboBox, SIGNAL(currentIndexChanged(int)), SLOT(selectType()));
    const auto types = QList<DatabaseSharing::Type>() << DatabaseSharing::Inactive << DatabaseSharing::ImportFrom
                                                      << DatabaseSharing::ExportTo << DatabaseSharing::SynchronizeWith;
    for (const DatabaseSharing::Type& type : types) {
        QString name;
        switch (type) {
        case DatabaseSharing::Inactive:
            name = tr("Inactive");
            break;
        case DatabaseSharing::ImportFrom:
            name = tr("Import from path");
            break;
        case DatabaseSharing::ExportTo:
            name = tr("Export to path");
            break;
        case DatabaseSharing::SynchronizeWith:
            name = tr("Synchronize with path");
            break;
        }
        m_ui->typeComboBox->insertItem(type, name, static_cast<int>(type));
    }
}

GroupSharingWidget::~GroupSharingWidget()
{
}

void GroupSharingWidget::setGroup(const Group* group)
{
    m_currentGroup = group;

    update();
}

void GroupSharingWidget::setCustomData(CustomData* customData)
{
    if (m_customData) {
        m_customData->disconnect(this);
    }

    m_customData = customData;

    if (m_customData) {
        connect(m_customData, SIGNAL(modified()), SLOT(update()));
    }

    update();
}

void GroupSharingWidget::showSharingState()
{
    if(!m_currentGroup->database()){
        return;
    }
    const bool importEnabled = DatabaseSharing::isEnabled(m_currentGroup->database(), DatabaseSharing::ImportFrom);
    const bool exportEnabled = DatabaseSharing::isEnabled(m_currentGroup->database(), DatabaseSharing::ExportTo);
    if (!importEnabled && !exportEnabled) {
        m_ui->messageWidget->showMessage(tr("Database sharing is disabled"), MessageWidget::Information);
    }
    if (importEnabled && !exportEnabled) {
        m_ui->messageWidget->showMessage(tr("Database export is disabled"), MessageWidget::Information);
    }
    if (!importEnabled && exportEnabled) {
        m_ui->messageWidget->showMessage(tr("Database import is disabled"), MessageWidget::Information);
    }
}

void GroupSharingWidget::update()
{
    if (!m_customData || !m_currentGroup) {
        m_ui->passwordEdit->clear();
        m_ui->pathEdit->clear();
        m_ui->passwordGenerator->hide();
        m_ui->togglePasswordGeneratorButton->setChecked(false);

    } else {
        const DatabaseSharing::Reference reference = DatabaseSharing::referenceOf(m_customData);

        m_ui->typeComboBox->setCurrentIndex(reference.type);
        m_ui->passwordEdit->setText(reference.password);
        m_ui->pathEdit->setText(reference.path);

        showSharingState();
    }
}

void GroupSharingWidget::togglePasswordGeneratorButton(bool checked)
{
    m_ui->passwordGenerator->regeneratePassword();
    m_ui->passwordGenerator->setVisible(checked);
}

void GroupSharingWidget::setGeneratedPassword(const QString& password)
{
    if (!m_customData) {
        return;
    }
    DatabaseSharing::Reference reference = DatabaseSharing::referenceOf(m_customData);
    reference.password = password;
    DatabaseSharing::setReferenceTo(m_customData, reference);
    m_ui->togglePasswordGeneratorButton->setChecked(false);
}

void GroupSharingWidget::setPath(const QString& path)
{
    if (!m_customData) {
        return;
    }
    DatabaseSharing::Reference reference = DatabaseSharing::referenceOf(m_customData);
    reference.path = path;
    DatabaseSharing::setReferenceTo(m_customData, reference);
}

void GroupSharingWidget::selectPath()
{
    if (!m_customData) {
        return;
    }
    QString defaultDirPath = config()->get("Sharing/LastSharingDir").toString();
    const bool dirExists = !defaultDirPath.isEmpty() && QDir(defaultDirPath).exists();
    if (!dirExists) {
        defaultDirPath = QStandardPaths::standardLocations(QStandardPaths::DocumentsLocation).first();
    }
    DatabaseSharing::Reference reference = DatabaseSharing::referenceOf(m_customData);
    QString filetype = tr("kdbx.share", "Filetype for sharing container");
    QString filters = QString("%1 (*." + filetype + ");;%2 (*)").arg(tr("KeePass2 Sharing Container"), tr("All files"));
    QString filename = reference.path;
    if (filename.isEmpty()) {
        filename = tr("%1.%2", "Template for sharing container").arg(m_currentGroup->name()).arg(filetype);
    }
    switch (reference.type) {
    case DatabaseSharing::ImportFrom:
        filename = fileDialog()->getFileName(this,
                                             tr("Select import source"),
                                             defaultDirPath,
                                             filters,
                                             nullptr,
                                             QFileDialog::DontConfirmOverwrite,
                                             filetype,
                                             filename);
        break;
    case DatabaseSharing::ExportTo:
        filename = fileDialog()->getFileName(
            this, tr("Select export target"), defaultDirPath, filters, nullptr, 0, filetype, filename);
        break;
    case DatabaseSharing::SynchronizeWith:
    case DatabaseSharing::Inactive:
        filename = fileDialog()->getFileName(
            this, tr("Select import/export file"), defaultDirPath, filters, nullptr, 0, filetype, filename);
        break;
    }

    if (filename.isEmpty()) {
        return;
    }

    setPath(filename);
    config()->set("Sharing/LastSharingDir", QFileInfo(filename).absolutePath());
}

void GroupSharingWidget::selectPassword()
{
    if (!m_customData) {
        return;
    }
    DatabaseSharing::Reference reference = DatabaseSharing::referenceOf(m_customData);
    reference.password = m_ui->passwordEdit->text();
    DatabaseSharing::setReferenceTo(m_customData, reference);
}

void GroupSharingWidget::selectType()
{
    if (!m_customData) {
        return;
    }
    DatabaseSharing::Reference reference = DatabaseSharing::referenceOf(m_customData);
    reference.type = static_cast<DatabaseSharing::Type>(m_ui->typeComboBox->currentData().toInt());
    DatabaseSharing::setReferenceTo(m_customData, reference);
}
