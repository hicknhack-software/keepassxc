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

#include "EditGroupWidgetKeeShare.h"
#include "ui_EditGroupWidgetKeeShare.h"

#include "core/Config.h"
#include "core/CustomData.h"
#include "core/FilePath.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "crypto/ssh/OpenSSHKey.h"
#include "gui/FileDialog.h"
#include "keeshare/KeeShare.h"
#include "keeshare/PathLineEdit.h"

#include <QDebug>
#include <QDir>
#include <QStandardPaths>

EditGroupWidgetKeeShare::EditGroupWidgetKeeShare(QWidget* parent)
    : QWidget(parent)
    , m_ui(new Ui::EditGroupWidgetKeeShare())
{
    m_ui->setupUi(this);

    m_ui->togglePasswordButton->setIcon(filePath()->onOffIcon("actions", "password-show"));
    m_ui->togglePasswordGeneratorButton->setIcon(filePath()->icon("actions", "password-generator", false));

    m_ui->passwordGenerator->layout()->setContentsMargins(0, 0, 0, 0);
    m_ui->passwordGenerator->hide();
    m_ui->passwordGenerator->reset();

    m_ui->messageWidget->hide();
    m_ui->messageWidget->setCloseButtonVisible(false);
    m_ui->messageWidget->setAutoHideTimeout(-1);

    connect(m_ui->togglePasswordButton, SIGNAL(toggled(bool)), m_ui->passwordEdit, SLOT(setShowPassword(bool)));
    connect(m_ui->togglePasswordGeneratorButton, SIGNAL(toggled(bool)), SLOT(togglePasswordGeneratorButton(bool)));
    connect(m_ui->passwordEdit, SIGNAL(textChanged(QString)), SLOT(selectPassword()));
    connect(m_ui->passwordGenerator, SIGNAL(appliedPassword(QString)), SLOT(setGeneratedPassword(QString)));
    connect(m_ui->pathEdit, SIGNAL(editingFinished()), SLOT(selectPath()));
    connect(m_ui->pathSelectionButton, SIGNAL(pressed()), SLOT(launchPathSelectionDialog()));
    connect(m_ui->typeComboBox, SIGNAL(currentIndexChanged(int)), SLOT(selectType()));
    connect(m_ui->clearButton, SIGNAL(clicked(bool)), SLOT(clearInputs()));

    connect(KeeShare::instance(), SIGNAL(activeChanged()), SLOT(showSharingState()));

    const auto types = QList<KeeShareSettings::Type>()
                       << KeeShareSettings::Inactive << KeeShareSettings::ImportFrom << KeeShareSettings::ExportTo
                       << KeeShareSettings::SynchronizeWith;
    for (const auto& type : types) {
        QString name;
        switch (type) {
        case KeeShareSettings::Inactive:
            name = tr("Inactive");
            break;
        case KeeShareSettings::ImportFrom:
            name = tr("Import");
            break;
        case KeeShareSettings::ExportTo:
            name = tr("Export");
            break;
        case KeeShareSettings::SynchronizeWith:
            name = tr("Synchronize");
            break;
        }
        m_ui->typeComboBox->insertItem(static_cast<int>(type), name, static_cast<int>(type));
    }

    addOverrides(m_ui->pathLocalOverridesLayout, { KeeShare::referenceSwitch() });
}

EditGroupWidgetKeeShare::~EditGroupWidgetKeeShare()
{
}

void EditGroupWidgetKeeShare::setGroup(Group* temporaryGroup, QSharedPointer<Database> database)
{
    if (m_temporaryGroup) {
        m_temporaryGroup->disconnect(this);
    }

    m_database = database;
    m_temporaryGroup = temporaryGroup;

    if (m_temporaryGroup) {
        connect(m_temporaryGroup, SIGNAL(groupModified()), SLOT(update()));
    }

    update();
}

void EditGroupWidgetKeeShare::showSharingState()
{
    if (!m_temporaryGroup) {
        return;
    }

    auto supportedExtensions = QStringList();
#if defined(WITH_XC_KEESHARE_INSECURE)
    supportedExtensions << KeeShare::unsignedContainerFileType();
#endif
#if defined(WITH_XC_KEESHARE_SECURE)
    supportedExtensions << KeeShare::signedContainerFileType();
#endif
    const auto reference = KeeShare::referenceOf(m_temporaryGroup);
    if (!KeeShare::unresolvedFilePath(reference).isEmpty()) {
        bool supported = false;
        for (const auto& extension : supportedExtensions) {
            if (KeeShare::unresolvedFilePath(reference).endsWith(extension, Qt::CaseInsensitive)) {
                supported = true;
                break;
            }
        }
        if (!supported) {
            m_ui->messageWidget->showMessage(tr("Your KeePassXC version does not support sharing this container type.\n"
                                                "Supported extensions are: %1.")
                                                 .arg(supportedExtensions.join(", ")),
                                             MessageWidget::Warning);
            return;
        }

        const auto groups = m_database->rootGroup()->groupsRecursive(true);
        bool conflictExport = false;
        bool multipleImport = false;
        bool cycleImportExport = false;
        for (const auto* group : groups) {
            if (group->uuid() == m_temporaryGroup->uuid()) {
                continue;
            }
            const auto other = KeeShare::referenceOf(group);
            if (KeeShare::unresolvedFilePath(other) != KeeShare::unresolvedFilePath(reference)) {
                continue;
            }
            multipleImport |= other.isImporting() && reference.isImporting();
            conflictExport |= other.isExporting() && reference.isExporting();
            cycleImportExport |=
                (other.isImporting() && reference.isExporting()) || (other.isExporting() && reference.isImporting());
        }
        if (conflictExport) {
            m_ui->messageWidget->showMessage(
                tr("%1 is already being exported by this database.").arg(KeeShare::unresolvedFilePath(reference)),
                MessageWidget::Error);
            return;
        }
        if (multipleImport) {
            m_ui->messageWidget->showMessage(
                tr("%1 is already being imported by this database.").arg(KeeShare::unresolvedFilePath(reference)),
                MessageWidget::Warning);
            return;
        }
        if (cycleImportExport) {
            m_ui->messageWidget->showMessage(
                tr("%1 is being imported and exported by different groups in this database.")
                    .arg(KeeShare::unresolvedFilePath(reference)),
                MessageWidget::Warning);
            return;
        }

        m_ui->messageWidget->hide();
    }
    const auto active = KeeShare::active();
    if (!active.in && !active.out) {
        m_ui->messageWidget->showMessage(
            tr("KeeShare is currently disabled. You can enable import/export in the application settings.",
               "KeeShare is a proper noun"),
            MessageWidget::Information);
        return;
    }
    if (active.in && !active.out) {
        m_ui->messageWidget->showMessage(tr("Database export is currently disabled by application settings."),
                                         MessageWidget::Information);
        return;
    }
    if (!active.in && active.out) {
        m_ui->messageWidget->showMessage(tr("Database import is currently disabled by application settings."),
                                         MessageWidget::Information);
        return;
    }
}

void EditGroupWidgetKeeShare::reset()
{
    m_ui->passwordEdit->clear();
    m_ui->pathEdit->clear();
    m_ui->pathOverrides->hide();
    while (m_ui->pathLocalOverridesLayout->rowCount() > 0) {
        m_ui->pathLocalOverridesLayout->removeRow(0);
    }
    while (m_ui->pathRemoteOverridesLayout->rowCount() > 0) {
        m_ui->pathRemoteOverridesLayout->removeRow(0);
    }
    m_overrideLabels.clear();
    m_overridePathEdits.clear();
    m_ui->typeComboBox->setCurrentIndex(KeeShareSettings::Inactive);
    m_ui->passwordGenerator->hide();
}

void EditGroupWidgetKeeShare::addOverrides(QFormLayout *layout, const QSet<QString> &keys)
{
    for (const auto &key : keys) {
        auto* systemLabel = new QLabel(m_ui->pathLocalOverrides);
        auto* pathLineEdit = new PathLineEdit(m_ui->pathLocalOverrides);
        Q_ASSERT(!m_overrideLabels.contains(key));
        Q_ASSERT(!m_overridePathEdits.contains(key));
        pathLineEdit->setDialogTitle(tr("Select an alternative share path"));
        pathLineEdit->setDialogDefaultDirectoryConfigKey("KeeShare/LastShareDir");
        m_overrideLabels[key] = systemLabel;
        m_overridePathEdits[key] = pathLineEdit;
        layout->addRow(systemLabel, pathLineEdit);
    }
}

void EditGroupWidgetKeeShare::removeOverrides(QFormLayout *layout, const QSet<QString> &keys)
{
    for (const auto &key : keys) {
        auto *systemLabel = m_overrideLabels.take(key);
        auto *pathLineEdit = m_overridePathEdits.take(key);
        if (systemLabel){
            layout->removeWidget(systemLabel);
            delete systemLabel;
        }
        if (pathLineEdit) {
            layout->removeWidget(pathLineEdit);
            delete pathLineEdit;
        }
    }
}

void EditGroupWidgetKeeShare::reinitialize()
{
    const auto reference = KeeShare::referenceOf(m_temporaryGroup);

    m_ui->typeComboBox->setCurrentIndex(static_cast<int>(reference.type));
    m_ui->passwordEdit->setText(reference.password);
    m_ui->pathEdit->setText(KeeShare::unresolvedFilePath(reference, ""));
    m_ui->pathLocalOverrides->show();
    m_ui->pathOverrides->setVisible(!reference.path.isEmpty());

    const auto currentKey = KeeShare::referenceSwitch();
    const auto currentKeys = QSet<QString>{ currentKey };
    const auto requestedKeys = reference.paths.keys().toSet();
    const auto existingKeys = m_overrideLabels.keys().toSet();
    const auto removedKeys = existingKeys - requestedKeys;
    const auto addedKeys = requestedKeys - existingKeys;

    addOverrides(m_ui->pathRemoteOverridesLayout, addedKeys - currentKeys);
    removeOverrides(m_ui->pathRemoteOverridesLayout, removedKeys - currentKeys);

    m_ui->pathLocalPreview->setText(KeeShare::resolvedFilePathWith(reference, *m_database));

    for (const auto &key : requestedKeys + currentKeys) {
        auto *systemLabel = m_overrideLabels[key];
        auto *pathLineEdit = m_overridePathEdits[key];
        systemLabel->setText(tr("Path to \"%1\" on \"%2\"").arg(reference.name).arg(key));
        systemLabel->setEnabled(key == currentKey);
        pathLineEdit->setPlaceholderPath(reference.path);
        pathLineEdit->setEnabled(key == currentKey);
        if (reference.paths.contains(key)){
            pathLineEdit->setPath(KeeShare::unresolvedPath(reference, key));
        }
    }


    showSharingState();
}

void EditGroupWidgetKeeShare::update()
{
    if (!m_temporaryGroup) {
        reset();
    } else {
        reinitialize();
    }

    m_ui->passwordGenerator->hide();
    m_ui->togglePasswordGeneratorButton->setChecked(false);
    m_ui->togglePasswordButton->setChecked(false);
}

void EditGroupWidgetKeeShare::clearInputs()
{
    if (m_temporaryGroup) {
        KeeShare::setReferenceTo(m_temporaryGroup, KeeShareSettings::Reference());
    }
    reset();
}

void EditGroupWidgetKeeShare::togglePasswordGeneratorButton(bool checked)
{
    m_ui->passwordGenerator->regeneratePassword();
    m_ui->passwordGenerator->setVisible(checked);
}

void EditGroupWidgetKeeShare::setGeneratedPassword(const QString& password)
{
    if (!m_temporaryGroup) {
        return;
    }
    auto reference = KeeShare::referenceOf(m_temporaryGroup);
    reference.password = password;
    KeeShare::setReferenceTo(m_temporaryGroup, reference);
    m_ui->togglePasswordGeneratorButton->setChecked(false);
}

void EditGroupWidgetKeeShare::selectPath()
{
    if (!m_temporaryGroup) {
        return;
    }
    auto reference = KeeShare::referenceOf(m_temporaryGroup);
    const auto switcher = KeeShare::referenceSwitch();
    const QFileInfo info(m_ui->pathEdit->text());
    reference.path = info.path();
    reference.name = info.fileName();
    KeeShare::setReferenceTo(m_temporaryGroup, reference);
}

void EditGroupWidgetKeeShare::launchPathSelectionDialog()
{
    if (!m_temporaryGroup) {
        return;
    }
    QString defaultDirPath = m_database->filePath();
    const bool dirExists = !defaultDirPath.isEmpty() && QDir(defaultDirPath).exists();
    if (!dirExists) {
        defaultDirPath = QStandardPaths::standardLocations(QStandardPaths::DocumentsLocation).first();
    }
    auto reference = KeeShare::referenceOf(m_temporaryGroup);
    QString defaultFiletype = "";
    auto supportedExtensions = QStringList();
    auto unsupportedExtensions = QStringList();
    auto knownFilters = QStringList() << QString("%1 (*)").arg("All files");
#if defined(WITH_XC_KEESHARE_INSECURE)
    defaultFiletype = KeeShare::unsignedContainerFileType();
    supportedExtensions << KeeShare::unsignedContainerFileType();
    knownFilters.prepend(
        QString("%1 (*.%2)").arg(tr("KeeShare unsigned container"), KeeShare::unsignedContainerFileType()));
#else
    unsupportedExtensions << KeeShare::unsignedContainerFileType();
#endif
#if defined(WITH_XC_KEESHARE_SECURE)
    defaultFiletype = KeeShare::signedContainerFileType();
    supportedExtensions << KeeShare::signedContainerFileType();
    knownFilters.prepend(
        QString("%1 (*.%2)").arg(tr("KeeShare signed container"), KeeShare::signedContainerFileType()));
#else
    unsupportedExtensions << KeeShare::signedContainerFileType();
#endif

    const auto filters = knownFilters.join(";;");
    auto filename = KeeShare::unresolvedFilePath(reference);
    if (filename.isEmpty()) {
        filename = m_temporaryGroup->name();
    }
    switch (reference.type) {
    case KeeShareSettings::ImportFrom:
        filename = fileDialog()->getFileName(this,
                                             tr("Select import source"),
                                             defaultDirPath,
                                             filters,
                                             nullptr,
                                             QFileDialog::DontConfirmOverwrite,
                                             defaultFiletype,
                                             filename);
        break;
    case KeeShareSettings::ExportTo:
        filename = fileDialog()->getFileName(this,
                                             tr("Select export target"),
                                             defaultDirPath,
                                             filters,
                                             nullptr,
                                             QFileDialog::Option(0),
                                             defaultFiletype,
                                             filename);
        break;
    case KeeShareSettings::SynchronizeWith:
    case KeeShareSettings::Inactive:
        filename = fileDialog()->getFileName(this,
                                             tr("Select import/export file"),
                                             defaultDirPath,
                                             filters,
                                             nullptr,
                                             QFileDialog::Option(0),
                                             defaultFiletype,
                                             filename);
        break;
    }

    if (filename.isEmpty()) {
        return;
    }
    bool validFilename = false;
    for (const auto& extension : supportedExtensions + unsupportedExtensions) {
        if (filename.endsWith(extension, Qt::CaseInsensitive)) {
            validFilename = true;
            break;
        }
    }
    if (!validFilename) {
        filename += (!filename.endsWith(".") ? "." : "") + defaultFiletype;
    }

    m_ui->pathEdit->setText(filename);
    selectPath();
}

void EditGroupWidgetKeeShare::selectPassword()
{
    if (!m_temporaryGroup) {
        return;
    }
    auto reference = KeeShare::referenceOf(m_temporaryGroup);
    reference.password = m_ui->passwordEdit->text();
    KeeShare::setReferenceTo(m_temporaryGroup, reference);
}

void EditGroupWidgetKeeShare::selectType()
{
    if (!m_temporaryGroup) {
        return;
    }
    auto reference = KeeShare::referenceOf(m_temporaryGroup);
    reference.type = static_cast<KeeShareSettings::Type>(m_ui->typeComboBox->currentData().toInt());
    KeeShare::setReferenceTo(m_temporaryGroup, reference);
}
