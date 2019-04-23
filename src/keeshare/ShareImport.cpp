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
#include "ShareImport.h"
#include "config-keepassx.h"
#include "core/Merger.h"
#include "format/KeePass2Reader.h"
#include "keeshare/KeeShare.h"
#include "keeshare/Signature.h"
#include "keys/PasswordKey.h"

#include <QMessageBox>
#include <QPushButton>

#if defined(WITH_XC_KEESHARE_SECURE)
#include <quazip5/quazip.h>
#include <quazip5/quazipfile.h>
#endif

namespace
{
    enum Trust
    {
        Invalid,
        Own,
        UntrustedForever,
        UntrustedOnce,
        TrustedOnce,
        TrustedForever,
    };

    QPair<Trust, KeeShareSettings::Certificate>
    check(QByteArray& data,
          const KeeShareSettings::Reference& reference,
          const KeeShareSettings::Certificate& ownCertificate,
          const QList<KeeShareSettings::ScopedCertificate>& knownCertificates,
          const KeeShareSettings::Sign& sign)
    {
        KeeShareSettings::Certificate certificate;
        if (!sign.signature.isEmpty()) {
            certificate = sign.certificate;
            auto key = sign.certificate.sshKey();
            key.openKey(QString());
            const auto signer = Signature();
            if (!signer.verify(data, sign.signature, key)) {
                qCritical("Invalid signature for shared container %s.",
                          qPrintable(KeeShare::unresolvedFilePath(reference)));
                return {Invalid, KeeShareSettings::Certificate()};
            }

            if (ownCertificate.key == sign.certificate.key) {
                return {Own, ownCertificate};
            }
        }
        enum Scope
        {
            Invalid,
            Global,
            Local
        };
        Scope scope = Invalid;
        KeeShareSettings::Trust trusted = KeeShareSettings::Trust::Ask;
        for (const auto& scopedCertificate : knownCertificates) {
            if (scopedCertificate.certificate.key == certificate.key
                && scopedCertificate.path == KeeShare::unresolvedFilePath(reference)) {
                // Global scope is overwritten by local scope
                scope = Global;
                trusted = scopedCertificate.trust;
            }
            if (scopedCertificate.certificate.key == certificate.key
                && scopedCertificate.path == KeeShare::unresolvedFilePath(reference)) {
                scope = Local;
                trusted = scopedCertificate.trust;
                break;
            }
        }
        if (scope != Invalid && trusted != KeeShareSettings::Trust::Ask) {
            // we introduce now scopes if there is a global
            return {trusted == KeeShareSettings::Trust::Trusted ? TrustedForever : UntrustedForever, certificate};
        }

        QMessageBox warning;
        if (sign.signature.isEmpty()) {
            warning.setIcon(QMessageBox::Warning);
            warning.setWindowTitle(ShareObserver::tr("Import from container without signature"));
            warning.setText(ShareObserver::tr("We cannot verify the source of the shared container because it is not "
                                              "signed. Do you really want to import from %1?")
                                .arg(KeeShare::unresolvedFilePath(reference)));
        } else {
            warning.setIcon(QMessageBox::Question);
            warning.setWindowTitle(ShareObserver::tr("Import from container with certificate"));
            warning.setText(
                ShareObserver::tr("Do you want to trust %1 with the fingerprint of %2 from %3?")
                    .arg(certificate.signer, certificate.fingerprint(), KeeShare::unresolvedFilePath(reference)));
        }
        auto untrustedOnce = warning.addButton(ShareObserver::tr("Not this time"), QMessageBox::ButtonRole::NoRole);
        auto untrustedForever = warning.addButton(ShareObserver::tr("Never"), QMessageBox::ButtonRole::NoRole);
        auto trustedForever = warning.addButton(ShareObserver::tr("Always"), QMessageBox::ButtonRole::YesRole);
        auto trustedOnce = warning.addButton(ShareObserver::tr("Just this time"), QMessageBox::ButtonRole::YesRole);
        warning.setDefaultButton(untrustedOnce);
        warning.exec();
        if (warning.clickedButton() == trustedForever) {
            return {TrustedForever, certificate};
        }
        if (warning.clickedButton() == trustedOnce) {
            return {TrustedOnce, certificate};
        }
        if (warning.clickedButton() == untrustedOnce) {
            return {UntrustedOnce, certificate};
        }
        if (warning.clickedButton() == untrustedForever) {
            return {UntrustedForever, certificate};
        }
        return {UntrustedOnce, certificate};
    }

    ShareObserver::Result
    signedContainerInto(const QString& resolvedPath, const KeeShareSettings::Reference& reference, Group* targetGroup)
    {
#if !defined(WITH_XC_KEESHARE_SECURE)
        Q_UNUSED(targetGroup);
        Q_UNUSED(resolvedPath);
        return {KeeShare::unresolvedPath(reference),
                ShareObserver::Result::Warning,
                ShareObserver::tr("Signed share container are not supported - import prevented")};
#else
        QuaZip zip(resolvedPath);
        if (!zip.open(QuaZip::mdUnzip)) {
            qCritical("Unable to open file %s.", qPrintable(KeeShare::unresolvedFilePath(reference)));
            return {KeeShare::unresolvedFilePath(reference),
                    ShareObserver::Result::Error,
                    ShareObserver::tr("File is not readable")};
        }
        const auto expected = QSet<QString>() << KeeShare::signatureFileName() << KeeShare::containerFileName();
        const auto files = zip.getFileInfoList();
        QSet<QString> actual;
        for (const auto& file : files) {
            actual << file.name;
        }
        if (expected != actual) {
            qCritical("Invalid sharing container %s.", qPrintable(KeeShare::unresolvedFilePath(reference)));
            return {KeeShare::unresolvedFilePath(reference),
                    ShareObserver::Result::Error,
                    ShareObserver::tr("Invalid sharing container")};
        }

        zip.setCurrentFile(KeeShare::signatureFileName());
        QuaZipFile signatureFile(&zip);
        signatureFile.open(QuaZipFile::ReadOnly);
        QTextStream stream(&signatureFile);

        const auto sign = KeeShareSettings::Sign::deserialize(stream.readAll());
        signatureFile.close();

        zip.setCurrentFile(KeeShare::containerFileName());
        QuaZipFile databaseFile(&zip);
        databaseFile.open(QuaZipFile::ReadOnly);
        auto payload = databaseFile.readAll();
        databaseFile.close();
        QBuffer buffer(&payload);
        buffer.open(QIODevice::ReadOnly);

        KeePass2Reader reader;
        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create(reference.password));
        auto sourceDb = QSharedPointer<Database>::create();
        if (!reader.readDatabase(&buffer, key, sourceDb.data())) {
            qCritical("Error while parsing the database: %s", qPrintable(reader.errorString()));
            return {KeeShare::unresolvedFilePath(reference), ShareObserver::Result::Error, reader.errorString()};
        }

        auto foreign = KeeShare::foreign();
        auto own = KeeShare::own();
        auto trust = check(payload, reference, own.certificate, foreign.certificates, sign);
        switch (trust.first) {
        case Invalid:
            qWarning("Prevent untrusted import");
            return {KeeShare::unresolvedFilePath(reference),
                    ShareObserver::Result::Error,
                    ShareObserver::tr("Untrusted import prevented")};

        case UntrustedForever:
        case TrustedForever: {
            bool found = false;
            const auto trusted =
                trust.first == TrustedForever ? KeeShareSettings::Trust::Trusted : KeeShareSettings::Trust::Untrusted;
            for (KeeShareSettings::ScopedCertificate& scopedCertificate : foreign.certificates) {
                if (scopedCertificate.certificate.key == trust.second.key
                    && scopedCertificate.path == KeeShare::unresolvedFilePath(reference)) {
                    scopedCertificate.certificate.signer = trust.second.signer;
                    scopedCertificate.path = KeeShare::unresolvedFilePath(reference);
                    scopedCertificate.trust = trusted;
                    found = true;
                    break;
                }
            }
            if (!found) {
                foreign.certificates << KeeShareSettings::ScopedCertificate{
                    KeeShare::unresolvedFilePath(reference), trust.second, trusted};
            }
            // update foreign certificates with new settings
            KeeShare::setForeign(foreign);

            if (trust.first == TrustedForever) {
                qDebug("Synchronize %s %s with %s",
                       qPrintable(KeeShare::unresolvedFilePath(reference)),
                       qPrintable(targetGroup->name()),
                       qPrintable(sourceDb->rootGroup()->name()));
                Merger merger(sourceDb->rootGroup(), targetGroup);
                merger.setForcedMergeMode(Group::Synchronize);
                const bool changed = merger.merge();
                if (changed) {
                    return {KeeShare::unresolvedFilePath(reference),
                            ShareObserver::Result::Success,
                            ShareObserver::tr("Successful signed import")};
                }
            }
            // Silent ignore of untrusted import or unchanging import
            return {};
        }
        case TrustedOnce:
        case Own: {
            qDebug("Synchronize %s %s with %s",
                   qPrintable(KeeShare::unresolvedFilePath(reference)),
                   qPrintable(targetGroup->name()),
                   qPrintable(sourceDb->rootGroup()->name()));
            Merger merger(sourceDb->rootGroup(), targetGroup);
            merger.setForcedMergeMode(Group::Synchronize);
            const bool changed = merger.merge();
            if (changed) {
                return {KeeShare::unresolvedFilePath(reference),
                        ShareObserver::Result::Success,
                        ShareObserver::tr("Successful signed import")};
            }
            return {};
        }
        default:
            Q_ASSERT(false);
            return {KeeShare::unresolvedFilePath(reference),
                    ShareObserver::Result::Error,
                    ShareObserver::tr("Unexpected error")};
        }
#endif
    }

    ShareObserver::Result
    unsignedContainerInto(const QString& resolvedPath, const KeeShareSettings::Reference& reference, Group* targetGroup)
    {
#if !defined(WITH_XC_KEESHARE_INSECURE)
        Q_UNUSED(targetGroup);
        Q_UNUSED(resolvedPath);
        return {KeeShare::unresolvedPath(reference),
                ShareObserver::Result::Warning,
                ShareObserver::tr("Unsigned share container are not supported - import prevented")};
#else
        QFile file(resolvedPath);
        if (!file.open(QIODevice::ReadOnly)) {
            qCritical("Unable to open file %s.", qPrintable(KeeShare::unresolvedFilePath(reference)));
            return {KeeShare::unresolvedFilePath(reference),
                    ShareObserver::Result::Error,
                    ShareObserver::tr("File is not readable")};
        }
        auto payload = file.readAll();
        file.close();
        QBuffer buffer(&payload);
        buffer.open(QIODevice::ReadOnly);

        KeePass2Reader reader;
        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create(reference.password));
        auto sourceDb = QSharedPointer<Database>::create();
        if (!reader.readDatabase(&buffer, key, sourceDb.data())) {
            qCritical("Error while parsing the database: %s", qPrintable(reader.errorString()));
            return {KeeShare::unresolvedFilePath(reference), ShareObserver::Result::Error, reader.errorString()};
        }

        auto foreign = KeeShare::foreign();
        const auto own = KeeShare::own();
        const auto sign = KeeShareSettings::Sign(); // invalid sign
        auto trust = check(payload, reference, own.certificate, foreign.certificates, sign);
        switch (trust.first) {
        case UntrustedForever:
        case TrustedForever: {
            bool found = false;
            const auto trusted =
                trust.first == TrustedForever ? KeeShareSettings::Trust::Trusted : KeeShareSettings::Trust::Untrusted;
            for (KeeShareSettings::ScopedCertificate& scopedCertificate : foreign.certificates) {
                if (scopedCertificate.certificate.key == trust.second.key
                    && scopedCertificate.path == KeeShare::unresolvedFilePath(reference)) {
                    scopedCertificate.certificate.signer = trust.second.signer;
                    scopedCertificate.path = KeeShare::unresolvedFilePath(reference);
                    scopedCertificate.trust = trusted;
                    found = true;
                    break;
                }
            }
            if (!found) {
                foreign.certificates << KeeShareSettings::ScopedCertificate{
                    KeeShare::unresolvedFilePath(reference), trust.second, trusted};
            }
            // update foreign certificates with new settings
            KeeShare::setForeign(foreign);

            if (trust.first == TrustedForever) {
                qDebug("Synchronize %s %s with %s",
                       qPrintable(KeeShare::unresolvedFilePath(reference)),
                       qPrintable(targetGroup->name()),
                       qPrintable(sourceDb->rootGroup()->name()));
                Merger merger(sourceDb->rootGroup(), targetGroup);
                merger.setForcedMergeMode(Group::Synchronize);
                const bool changed = merger.merge();
                if (changed) {
                    return {KeeShare::unresolvedFilePath(reference),
                            ShareObserver::Result::Success,
                            ShareObserver::tr("Successful signed import")};
                }
            }
            return {};
        }

        case TrustedOnce: {
            qDebug("Synchronize %s %s with %s",
                   qPrintable(KeeShare::unresolvedFilePath(reference)),
                   qPrintable(targetGroup->name()),
                   qPrintable(sourceDb->rootGroup()->name()));
            Merger merger(sourceDb->rootGroup(), targetGroup);
            merger.setForcedMergeMode(Group::Synchronize);
            const bool changed = merger.merge();
            if (changed) {
                return {KeeShare::unresolvedFilePath(reference),
                        ShareObserver::Result::Success,
                        ShareObserver::tr("Successful unsigned import")};
            }
            return {};
        }
        default:
            qWarning("Prevent untrusted import");
            return {KeeShare::unresolvedFilePath(reference),
                    ShareObserver::Result::Warning,
                    ShareObserver::tr("Untrusted import prevented")};
        }
#endif
    }

} // namespace

ShareObserver::Result ShareImport::containerInto(const QString& resolvedPath,
                                                 const KeeShareSettings::Reference& reference,
                                                 Group* targetGroup)
{
    const QFileInfo info(resolvedPath);
    if (!info.exists()) {
        qCritical("File %s does not exist.", qPrintable(info.absoluteFilePath()));
        return {KeeShare::unresolvedFilePath(reference),
                ShareObserver::Result::Warning,
                ShareObserver::tr("File does not exist")};
    }

    if (KeeShare::isContainerType(info, KeeShare::signedContainerFileType())) {
        return signedContainerInto(resolvedPath, reference, targetGroup);
    }
    if (KeeShare::isContainerType(info, KeeShare::unsignedContainerFileType())) {
        return unsignedContainerInto(resolvedPath, reference, targetGroup);
    }
    return {KeeShare::unresolvedFilePath(reference),
            ShareObserver::Result::Error,
            ShareObserver::tr("Unknown share container type")};
}
