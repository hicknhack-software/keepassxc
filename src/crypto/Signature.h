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

#ifndef KEEPASSXC_SIGNATURE_H
#define KEEPASSXC_SIGNATURE_H

#include <gcrypt.h>
#include <QByteArray>
#include <QString>

class OpenSSHKey;

class Signature
{
public:
    static QString create(const QByteArray& data, const OpenSSHKey& key);
    static bool verify(const QByteArray& data, const QString &signature, const OpenSSHKey &key);

};

#endif // KEEPASSXC_SIGNATURE_H
