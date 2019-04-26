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
    connect(m_ui->pathLineEdit, SIGNAL(pathChanged(QString)), SLOT(selectPath()));
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

    const auto selector = KeeShare::pathSelector();
    addOverrides(m_ui->pathLocalOverridesLayout, {selector});
    connect(m_overridePathEdits[selector], &PathLineEdit::pathChanged, [this, selector](const QString& path) {
        if (m_temporaryGroup) {
            auto reference = KeeShare::referenceOf(m_temporaryGroup);
            if (!path.isEmpty()) {
                reference.overridePaths[selector] = path;
            } else {
                reference.overridePaths.remove(selector);
            }
            KeeShare::setReferenceTo(m_temporaryGroup, reference);
        }
    });
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
    m_ui->pathLineEdit->clear();
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

void EditGroupWidgetKeeShare::addOverrides(QFormLayout* layout, const QSet<QString>& keys)
{
    for (const auto& key : keys) {
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

void EditGroupWidgetKeeShare::removeOverrides(QFormLayout* layout, const QSet<QString>& keys)
{
    for (const auto& key : keys) {
        auto* systemLabel = m_overrideLabels.take(key);
        auto* pathLineEdit = m_overridePathEdits.take(key);
        if (systemLabel) {
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
    m_ui->passwordEdit->setText(reference.containerPassword);
    m_ui->pathLocalOverrides->show();
    m_ui->pathOverrides->setVisible(!reference.standardPath.isEmpty());

    const auto currentSelector = KeeShare::pathSelector();
    const auto currentSelectors = QSet<QString>{currentSelector};
    const auto requestedSelectors = reference.overridePaths.keys().toSet();
    const auto existingSelectors = m_overrideLabels.keys().toSet();
    const auto removedSelectors = existingSelectors - requestedSelectors;
    const auto addedSelectors = requestedSelectors - existingSelectors;

    addOverrides(m_ui->pathRemoteOverridesLayout, addedSelectors - currentSelectors);
    removeOverrides(m_ui->pathRemoteOverridesLayout, removedSelectors - currentSelectors);

    m_ui->pathLocalPreview->setText(KeeShare::resolvedFilePathWith(reference, *m_database));

    for (const auto& selector : requestedSelectors + currentSelectors) {
        auto* systemLabel = m_overrideLabels[selector];
        auto* pathLineEdit = m_overridePathEdits[selector];
        systemLabel->setText(tr("Path to \"%1\" on \"%2\"").arg(reference.containerName).arg(selector));
        systemLabel->setEnabled(selector == currentSelector);
        pathLineEdit->setPlaceholderPath(reference.standardPath);
        pathLineEdit->setEnabled(selector == currentSelector);
        pathLineEdit->setType(PathLineEdit::SelectDirectory);
        if (reference.overridePaths.contains(selector)) {
            pathLineEdit->setPath(KeeShare::unresolvedPath(reference, selector));
        }
    }

    m_ui->pathLineEdit->setPath(KeeShare::unresolvedFilePath(reference, ""));
    switch (reference.type) {
    case KeeShareSettings::ImportFrom:
        m_ui->pathLineEdit->setDialogTitle(tr("Select import source"));
        m_ui->pathLineEdit->setType(PathLineEdit::SelectReadFile);
        break;
    case KeeShareSettings::ExportTo:
        m_ui->pathLineEdit->setDialogTitle(tr("Select export target"));
        m_ui->pathLineEdit->setType(PathLineEdit::SelectWriteFile);
        break;
    case KeeShareSettings::SynchronizeWith:
        m_ui->pathLineEdit->setDialogTitle(tr("Select import/export file"));
        m_ui->pathLineEdit->setType(PathLineEdit::SelectWriteFile);
        break;
    }

    auto supported = QList<QPair<QString, QString>>{{QString(), tr("All files")}};
    auto unsupported = QList<QString>();
    auto defaultExtension = QString();
#if defined(WITH_XC_KEESHARE_INSECURE)
    defaultExtension = KeeShare::unsignedContainerFileType();
    supported.prepend({KeeShare::unsignedContainerFileType(), tr("KeeShare unsigned container")});
#else
    unsupported.prepend(KeeShare::unsignedContainerFileType());
#endif

#if defined(WITH_XC_KEESHARE_SECURE)
    defaultExtension = KeeShare::signedContainerFileType();
    supported.prepend({KeeShare::signedContainerFileType(), tr("KeeShare signed container")});
#else
    unsupported.prepend(KeeShare::signedContainerFileType());
#endif
    m_ui->pathLineEdit->setDialogSupportedExtensions(supported, defaultExtension);
    m_ui->pathLineEdit->setDialogUnsupportedExtensions(unsupported);

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
    reference.containerPassword = password;
    KeeShare::setReferenceTo(m_temporaryGroup, reference);
    m_ui->togglePasswordGeneratorButton->setChecked(false);
}

void EditGroupWidgetKeeShare::selectPath()
{
    if (!m_temporaryGroup) {
        return;
    }
    auto reference = KeeShare::referenceOf(m_temporaryGroup);
    // const QFileInfo info(m_ui->pathEdit->text());
    const QFileInfo info(m_ui->pathLineEdit->path());
    reference.standardPath = info.path();
    reference.containerName = info.fileName();
    KeeShare::setReferenceTo(m_temporaryGroup, reference);
}

void EditGroupWidgetKeeShare::selectPassword()
{
    if (!m_temporaryGroup) {
        return;
    }
    auto reference = KeeShare::referenceOf(m_temporaryGroup);
    reference.containerPassword = m_ui->passwordEdit->text();
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
