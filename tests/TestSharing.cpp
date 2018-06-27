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
#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "config-keepassx-tests.h"
#include "core/Metadata.h"
#include "crypto/Random.h"
#include "crypto/Crypto.h"
#include "crypto/ssh/OpenSSHKey.h"
#include "sharing/SharingSettings.h"
#include "format/KeePass2Writer.h"
#include "keys/PasswordKey.h"

#include <format/KeePass2Reader.h>


QTEST_GUILESS_MAIN(TestSharing)

Q_DECLARE_METATYPE(SharingSettings::Key)
Q_DECLARE_METATYPE(SharingSettings::Certificate)
Q_DECLARE_METATYPE(QList<SharingSettings::Certificate>)

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

void TestSharing::testNullObjects()
{
    const QString empty;
    QXmlStreamReader keyReader(empty);

    const SharingSettings::Key nullKey;
    QVERIFY(nullKey.isNull());
    const SharingSettings::Key xmlKey = SharingSettings::Key::deserialize(keyReader);
    QVERIFY(xmlKey.isNull());

    const SharingSettings::Certificate certificate;
    QVERIFY(certificate.isNull());
    const SharingSettings::Certificate xmlCertificate = SharingSettings::Certificate::deserialize(keyReader);
    QVERIFY(xmlCertificate.isNull());

    const SharingSettings nullSettings;
    QVERIFY(nullSettings.isNull());
    const SharingSettings xmlSettings = SharingSettings::deserialize(empty);
    QVERIFY(xmlSettings.isNull());
}

void TestSharing::testCertificateSerialization()
{
    QFETCH(bool, trusted);
    const OpenSSHKey &key = stubkey();
    SharingSettings::Certificate original;
    original.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Public, key);
    original.signer = "Some <!> &#_\"\" weird string";
    original.trusted = trusted;

    QString buffer;
    QXmlStreamWriter writer(&buffer);
    writer.writeStartDocument();
    SharingSettings::Certificate::serialize(writer, original, "Certificate");
    writer.writeEndDocument();
    QXmlStreamReader reader(buffer);
    SharingSettings::Certificate restored = SharingSettings::Certificate::deserialize(reader, "Certificate");

    QCOMPARE(restored.key, original.key);
    QCOMPARE(restored.signer, original.signer);
    QCOMPARE(restored.trusted, original.trusted);

    QCOMPARE(restored.sshKey().publicParts(), key.publicParts());
}

void TestSharing::testCertificateSerialization_data()
{
    QTest::addColumn<bool>("trusted");
    QTest::newRow("Trusted") << true;
    QTest::newRow("Untrusted") << false;
}

void TestSharing::testKeySerialization()
{
    const OpenSSHKey &key = stubkey();
    SharingSettings::Key original;
    original.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Private, key);

    QString buffer;
    QXmlStreamWriter writer(&buffer);
    writer.writeStartDocument();
    SharingSettings::Key::serialize(writer, original, "Key");
    writer.writeEndDocument();
    QXmlStreamReader reader(buffer);
    SharingSettings::Key restored = SharingSettings::Key::deserialize(reader, "Key");

    QCOMPARE(restored.key, original.key);
    QCOMPARE(restored.sshKey().privateParts(), key.privateParts());
    QCOMPARE(restored.sshKey().type(), key.type());
}

void TestSharing::testSettingsSerialization()
{

    QFETCH(bool, importing);
    QFETCH(bool, exporting);
    QFETCH(SharingSettings::Certificate, ownCertificate);
    QFETCH(SharingSettings::Key, ownKey);
    QFETCH(QList<SharingSettings::Certificate>, foreignCertificates);

    SharingSettings original;
    original.importing = importing;
    original.exporting = exporting;
    original.ownCertificate = ownCertificate;
    original.ownKey = ownKey;
    original.foreignCertificates = foreignCertificates;

    const QString serialized = SharingSettings::serialize(original);
    SharingSettings restored = SharingSettings::deserialize(serialized);

    QCOMPARE(restored.importing, importing);
    QCOMPARE(restored.exporting, exporting);
    QCOMPARE(restored.ownCertificate.key, ownCertificate.key);
    QCOMPARE(restored.ownCertificate.trusted, ownCertificate.trusted);
    QCOMPARE(restored.ownKey.key, ownKey.key);
    QCOMPARE(restored.foreignCertificates.count(), foreignCertificates.count());
    for( int i = 0; i < foreignCertificates.count(); ++i ){
        QCOMPARE(restored.foreignCertificates[i].key, foreignCertificates[i].key);
    }
}

void TestSharing::testSettingsSerialization_data()
{
    const OpenSSHKey &sshKey0 = stubkey(0);
    SharingSettings::Certificate certificate0;
    certificate0.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Public, sshKey0);
    certificate0.signer = "Some <!> &#_\"\" weird string";
    certificate0.trusted = true;

    SharingSettings::Key key0;
    key0.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Private, sshKey0);

    const OpenSSHKey &sshKey1 = stubkey(1);
    SharingSettings::Certificate certificate1;
    certificate1.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Public, sshKey1);
    certificate1.signer = "Another ";
    certificate1.trusted = true;

    QTest::addColumn<bool>("importing");
    QTest::addColumn<bool>("exporting");
    QTest::addColumn<SharingSettings::Certificate>("ownCertificate");
    QTest::addColumn<SharingSettings::Key>("ownKey");
    QTest::addColumn<QList<SharingSettings::Certificate>>("foreignCertificates");
    QTest::newRow("1") << false << false << SharingSettings::Certificate() << SharingSettings::Key() << QList<SharingSettings::Certificate>();
    QTest::newRow("2") << true << false << SharingSettings::Certificate() << SharingSettings::Key() << QList<SharingSettings::Certificate>();
    QTest::newRow("3") << true << true << SharingSettings::Certificate() << SharingSettings::Key() << QList<SharingSettings::Certificate>({ certificate0, certificate1 });
    QTest::newRow("4") << false << true << certificate0 << key0 << QList<SharingSettings::Certificate>();
    QTest::newRow("5") << false << false << certificate0 << key0 << QList<SharingSettings::Certificate>({ certificate1 });
}

const OpenSSHKey &TestSharing::stubkey(int index)
{
    static QMap<int, OpenSSHKey*> keys;
    if( !keys.contains(index)){
        OpenSSHKey *key = new OpenSSHKey(OpenSSHKey::generate(false));
        key->setParent(this);
        keys[index] = key;
    }
    return *keys[index];
}
