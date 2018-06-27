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

#include "DatabaseSettingsWidgetSharing.h"
#include "ui_DatabaseSettingsWidgetSharing.h"

#include "core/Database.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "sharing/Sharing.h"
#include "sharing/SharingSettings.h"

#include <QStandardItemModel>
#include <QMessageBox>

DatabaseSettingsWidgetSharing::DatabaseSettingsWidgetSharing(QWidget* parent)
    : QWidget(parent)
    , m_ui(new Ui::DatabaseSettingsWidgetSharing())
{
    m_ui->setupUi(this);

    connect(m_ui->verificationExporterEdit, SIGNAL(textChanged(QString)), SLOT(setVerificationExporter(QString)));
    connect(m_ui->generateCerticateButton, SIGNAL(clicked(bool)), SLOT(generateCerticate()));
    connect(m_ui->clearCertificateButton, SIGNAL(clicked(bool)), SLOT(clearCerticate()));
}

DatabaseSettingsWidgetSharing::~DatabaseSettingsWidgetSharing()
{
}

void DatabaseSettingsWidgetSharing::loadSettings(Database *db)
{
    m_db = db;

    SharingSettings settings = m_db ? Sharing::settingsOf(m_db) : SharingSettings();
    m_sharingInformation = SharingSettings::serialize(settings);
    m_ui->enableExportCheckBox->setChecked(settings.exporting);
    m_ui->enableImportCheckBox->setChecked(settings.importing);

    m_referencesModel.reset(new QStandardItemModel());
    m_verificationModel.reset(new QStandardItemModel());

    m_referencesModel->setHorizontalHeaderLabels(QStringList() << tr("Breadcrumb") << tr("Type") << tr("Path") << tr("Last Signer") << tr("Certificates"));
    const QList<Group*> groups = db->rootGroup()->groupsRecursive(true);
    for (const Group* group : groups) {
        if (!Sharing::isShared(group)) {
            continue;
        }
        const Sharing::Reference reference = Sharing::referenceOf(group->customData());

        QStringList hierarchy = group->hierarchy();
        hierarchy.removeFirst();
        QList<QStandardItem*> row = QList<QStandardItem*>();
        row << new QStandardItem(hierarchy.join(" > "));
        row << new QStandardItem(Sharing::referenceTypeLabel(reference));
        row << new QStandardItem(reference.path);
        m_referencesModel->appendRow(row);
    }

    m_ui->verificationExporterEdit->setText(settings.ownCertificate.signer);
    m_ui->verificationOwnCertificateEdit->setText(settings.ownCertificate.sshKey().publicKey());
    m_ui->verificationOwnKeyEdit->setText(settings.ownKey.sshKey().privateKey());
    m_ui->verificationOwnFingerprintEdit->setText(settings.ownCertificate.fingerprint());

    m_verificationModel->setHorizontalHeaderLabels(QStringList() << tr("Source") << tr("Status") << tr("Fingerprint") << tr("Certificate"));

    for( const SharingSettings::Certificate &certificate : settings.foreignCertificates ){
        QStandardItem* signer = new QStandardItem(certificate.signer);
        QStandardItem* verified = new QStandardItem(certificate.trusted ? tr("trusted") : tr("untrusted"));
        QStandardItem* fingerprint = new QStandardItem(certificate.fingerprint());
        QStandardItem* key = new QStandardItem(certificate.sshKey().publicKey());
        m_verificationModel->appendRow(QList<QStandardItem*>() << signer << verified << fingerprint << key);
    }

    m_ui->verificationTableView->setModel(m_verificationModel.data());
    m_ui->sharedGroupsView->setModel(m_referencesModel.data());
}

bool DatabaseSettingsWidgetSharing::saveSettings()
{
    SharingSettings settings = SharingSettings::deserialize(m_sharingInformation);
    settings.exporting = m_ui->enableExportCheckBox->isChecked();
    settings.importing = m_ui->enableImportCheckBox->isChecked();
    // TODO HNH: This depends on the order of saving new data - a better model would be to
    //           store changes to the settings in a temporary object and check on the final values
    //           of this object (similar scheme to Entry) - this way we could validate the settings before save
    if (settings.importing && m_db->metadata()->historyMaxItems() < 2 ) {
        QMessageBox warning;
        warning.setIcon(QMessageBox::Warning);
        warning.setWindowTitle(
            tr("Synchronization without history", "Title for warning about missing synchronization history"));
        warning.setText(
            tr("You are trying to import remote changes to your database without a sufficent history size.\n\n"
               "If you do not increase the history size to at least 2 you may suffer data loss!"));
        auto ok = warning.addButton(tr("Understood, import remote changes"), QMessageBox::ButtonRole::AcceptRole);
        auto cancel = warning.addButton(tr("Cancel"), QMessageBox::ButtonRole::RejectRole);
        warning.setDefaultButton(cancel);
        warning.exec();
        if (warning.clickedButton() != ok) {
            return false;
        }
    }

    Sharing::setSettingsTo(m_db, settings);
    return true;
}


void DatabaseSettingsWidgetSharing::setVerificationExporter(const QString &signer)
{
    SharingSettings settings = SharingSettings::deserialize(m_sharingInformation);
    settings.ownCertificate.signer = signer;
    m_ui->verificationExporterEdit->setText(settings.ownCertificate.signer);
    m_sharingInformation = SharingSettings::serialize(settings);
}

void DatabaseSettingsWidgetSharing::generateCerticate()
{
    SharingSettings settings = SharingSettings::generateEncryptionSettingsFor(m_db);
    m_ui->verificationOwnCertificateEdit->setText(settings.ownCertificate.sshKey().publicKey());
    m_ui->verificationOwnKeyEdit->setText(settings.ownKey.sshKey().privateKey());
    m_ui->verificationOwnFingerprintEdit->setText(settings.ownCertificate.fingerprint());
    m_sharingInformation = SharingSettings::serialize(settings);
}

void DatabaseSettingsWidgetSharing::clearCerticate()
{
    SharingSettings settings;
    m_ui->verificationExporterEdit->clear();
    m_ui->verificationOwnKeyEdit->clear();
    m_ui->verificationOwnCertificateEdit->clear();
    m_ui->verificationOwnFingerprintEdit->clear();
    m_sharingInformation = SharingSettings::serialize(settings);
}

