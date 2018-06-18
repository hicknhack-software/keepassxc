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

#include "TestSharing.h"
#include "TestGlobal.h"
#include "stub/TestRandom.h"

#include <QBuffer>
#include <QSignalSpy>
#include <QTemporaryFile>

#include "config-keepassx-tests.h"
#include "core/Metadata.h"
#include "crypto/Random.h"
#include "crypto/Crypto.h"
#include "format/KeePass2Writer.h"
#include "keys/PasswordKey.h"

#include <format/KeePass2Reader.h>

QTEST_GUILESS_MAIN(TestSharing)

void TestSharing::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestSharing::cleanupTestCase()
{
    TestRandom::teardown();
}

void TestSharing::testIdempotentDatabaseWriting()
{
    QScopedPointer<Database> db(new Database());

    Group* sharingGroup = new Group();
    sharingGroup->setName("SharingGroup");
    sharingGroup->setUuid(Uuid::random());
    sharingGroup->setParent(db->rootGroup());

    Entry* entry1 = new Entry();
    entry1->setUuid(Uuid::random());
    entry1->beginUpdate();
    entry1->setTitle("Entry1");
    entry1->endUpdate();
    entry1->setGroup(sharingGroup);

    Entry* entry2 = new Entry();
    entry2->setUuid(Uuid::random());
    entry2->beginUpdate();
    entry2->setTitle("Entry2");
    entry2->endUpdate();
    entry2->setGroup(sharingGroup);

    // prevent from changes introduced by randomization
    TestRandom::setup(new RandomBackendNull());

    QByteArray bufferOriginal;
    {
        QBuffer device(&bufferOriginal);
        device.open(QIODevice::ReadWrite);
        KeePass2Writer writer;
        writer.writeDatabase(&device, db.data());
    }

    QByteArray bufferCopy;
    {
        QBuffer device(&bufferCopy);
        device.open(QIODevice::ReadWrite);
        KeePass2Writer writer;
        writer.writeDatabase(&device, db.data());
    }

    QCOMPARE(bufferCopy, bufferOriginal);
}
