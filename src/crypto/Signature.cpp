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

#include "Signature.h"
#include "crypto/Crypto.h"
#include "crypto/CryptoHash.h"
#include "crypto/OpenSSHKey.h"
#include "crypto/Tool.h"

#include <QByteArray>
#include <gcrypt.h>

struct RSASigner
{
    gcry_error_t rc;
    QString error;

    void raiseError(const QString& message = QString())
    {
        if (message.isEmpty()) {
            error = QString("%1/%2").arg(QString::fromLocal8Bit(gcry_strsource(rc)),
                                         QString::fromLocal8Bit(gcry_strerror(rc)));
        } else {
            error = message;
        }
    }

    RSASigner()
        : rc(GPG_ERR_NO_ERROR)
    {
    }

    QString sign(const QByteArray& data, const OpenSSHKey& key)
    {
        enum Index
        {
            N,
            E,
            D,
            P,
            Q,
            U, // private key
            R,
            S, // signature

            Data,
            Key,
            Sig
        };

        const QByteArray block = CryptoHash::hash(data, CryptoHash::Sha256);

        Tool::GMap<Index, gcry_mpi_t, &gcry_mpi_release> mpi;
        Tool::GMap<Index, gcry_sexp_t, &gcry_sexp_release> sexp;
        const gcry_mpi_format format = GCRYMPI_FMT_USG;
        const QList<QByteArray> parts = key.privateParts();
        rc = gcry_mpi_scan(&mpi[N], format, parts[0].data(), parts[0].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        rc = gcry_mpi_scan(&mpi[E], format, parts[1].data(), parts[1].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        rc = gcry_mpi_scan(&mpi[D], format, parts[2].data(), parts[2].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        rc = gcry_mpi_scan(&mpi[U], format, parts[3].data(), parts[3].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        rc = gcry_mpi_scan(&mpi[P], format, parts[4].data(), parts[4].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        rc = gcry_mpi_scan(&mpi[Q], format, parts[5].data(), parts[5].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        if (gcry_mpi_cmp(mpi[P], mpi[Q]) > 0) {
            // see https://www.gnupg.org/documentation/manuals/gcrypt/RSA-key-parameters.html#RSA-key-parameters
            gcry_mpi_swap(mpi[P], mpi[Q]);
            gcry_mpi_invm(mpi[U], mpi[P], mpi[Q]);
        }
        rc = gcry_sexp_build(&sexp[Key],
                             NULL,
                             "(private-key (rsa (n %m) (e %m) (d %m) (p %m) (q %m) (u %m)))",
                             mpi[N],
                             mpi[E],
                             mpi[D],
                             mpi[P],
                             mpi[Q],
                             mpi[U]);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }

        rc = gcry_pk_testkey(sexp[Key]);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }

        rc = gcry_sexp_build(&sexp[Data], NULL, "(data (flags pkcs1) (hash sha256 %b))", block.size(), block.data());
        // rc = gcry_sexp_build(&sexp[Data], NULL, "(data (flags raw) (value %b))", data.size(), data.data());
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        rc = gcry_pk_sign(&sexp[Sig], sexp[Data], sexp[Key]);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        // TODO CK: manage memory allocated by gcry (sexp_find, mpi_aprint, ...)
        sexp[S] = gcry_sexp_find_token(sexp[Sig], "s", 1);
        mpi[S] = gcry_sexp_nth_mpi(sexp[S], 1, GCRYMPI_FMT_USG);
        unsigned char* s_buffer = nullptr;
        size_t s_written = 0;
        rc = gcry_mpi_aprint(GCRYMPI_FMT_STD, &s_buffer, &s_written, mpi[S]);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return QString();
        }
        return QString("rsa|%1").arg(
            QString::fromLatin1(QByteArray(reinterpret_cast<char*>(s_buffer), s_written).toHex()));
    }

    bool verify(const QByteArray& data, const OpenSSHKey& key, const QString& signature)
    {
        const gcry_mpi_format format = GCRYMPI_FMT_USG;
        enum MPI
        {
            N,
            E, // public key
            R,
            S // signature
        };
        enum SEXP
        {
            Data,
            Key,
            Sig
        };
        const QByteArray block = CryptoHash::hash(data, CryptoHash::Sha256);

        Tool::GMap<MPI, gcry_mpi_t, &gcry_mpi_release> mpi;
        Tool::GMap<SEXP, gcry_sexp_t, &gcry_sexp_release> sexp;
        const QList<QByteArray> parts = key.publicParts();

        rc = gcry_mpi_scan(&mpi[E], format, parts[0].data(), parts[0].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return false;
        }
        rc = gcry_mpi_scan(&mpi[N], format, parts[1].data(), parts[1].size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return false;
        }
        rc = gcry_sexp_build(&sexp[Key], NULL, "(public-key (rsa (n %m) (e %m)))", mpi[N], mpi[E]);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return false;
        }

        QRegExp extractor("rsa\\|([a-f0-9]+)", Qt::CaseInsensitive);
        if (!extractor.exactMatch(signature) || extractor.captureCount() != 1) {
            raiseError("Could not unpack signature parts");
            return false;
        }
        const QByteArray sig_s = QByteArray::fromHex(extractor.cap(1).toLatin1());

        rc = gcry_mpi_scan(&mpi[S], GCRYMPI_FMT_STD, sig_s.data(), sig_s.size(), nullptr);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return false;
        }
        rc = gcry_sexp_build(&sexp[Sig], NULL, "(sig-val (rsa (s %m)))", mpi[S]);
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return false;
        }
        rc = gcry_sexp_build(&sexp[Data], NULL, "(data (flags pkcs1) (hash sha256 %b))", block.size(), block.data());
        // rc = gcry_sexp_build(&sexp[Data], NULL, "(data (flags raw) (value %b))", data.size(), data.data());
        if (rc != GPG_ERR_NO_ERROR) {
            raiseError();
            return false;
        }
        rc = gcry_pk_verify(sexp[Sig], sexp[Data], sexp[Key]);
        if (rc != GPG_ERR_NO_ERROR && rc != GPG_ERR_BAD_SIGNATURE) {
            raiseError();
            return false;
        }
        return rc != GPG_ERR_BAD_SIGNATURE;
    }
};

QString Signature::create(const QByteArray& data, const OpenSSHKey& key)
{
    // TODO HNH: currently we publish the signature in our own non-standard format - it would
    //           be better to use a standard format (like ASN1 - but this would be more easy
    //           when we integrate a proper library)
    //           Even more, we could publish standard self signed certificates with the container
    //           instead of the custom certificates
    if (key.privateType() == OpenSSHKey::TYPE_RSA_PRIVATE) {
        RSASigner signer;
        QString result = signer.sign(data, key);
        if (signer.rc != GPG_ERR_NO_ERROR) {
            ::qWarning() << signer.error;
        }
        return result;
    }
    ::qWarning() << "Unsupported Public/Private key format";
    return QString();
}

bool Signature::verify(const QByteArray& data, const QString& signature, const OpenSSHKey& key)
{
    if (key.privateType() == OpenSSHKey::TYPE_RSA_PRIVATE || key.privateType() == OpenSSHKey::TYPE_RSA_PUBLIC) {
        RSASigner signer;
        bool result = signer.verify(data, key, signature);
        if (signer.rc != GPG_ERR_NO_ERROR) {
            ::qWarning() << signer.error;
        }
        return result;
    }
    ::qWarning() << "Unsupported Public/Private key format";
    return false;
}
