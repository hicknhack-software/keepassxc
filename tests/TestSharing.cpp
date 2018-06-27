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
#include "format/KeePass2Writer.h"
#include "keeshare/KeeShareSettings.h"
#include "keys/PasswordKey.h"

#include <format/KeePass2Reader.h>


QTEST_GUILESS_MAIN(TestSharing)

Q_DECLARE_METATYPE(KeeShareSettings::Key)
Q_DECLARE_METATYPE(KeeShareSettings::Certificate)
Q_DECLARE_METATYPE(QList<KeeShareSettings::Certificate>)

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

    const KeeShareSettings::Key nullKey;
    QVERIFY(nullKey.isNull());
    const KeeShareSettings::Key xmlKey = KeeShareSettings::Key::deserialize(keyReader);
    QVERIFY(xmlKey.isNull());

    const KeeShareSettings::Certificate certificate;
    QVERIFY(certificate.isNull());
    const KeeShareSettings::Certificate xmlCertificate = KeeShareSettings::Certificate::deserialize(keyReader);
    QVERIFY(xmlCertificate.isNull());

    const KeeShareSettings nullSettings;
    QVERIFY(nullSettings.isNull());
    const KeeShareSettings xmlSettings = KeeShareSettings::deserialize(empty);
    QVERIFY(xmlSettings.isNull());
}

void TestSharing::testCertificateSerialization()
{
    QFETCH(bool, trusted);
    const OpenSSHKey &key = stubkey();
    KeeShareSettings::Certificate original;
    original.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Public, key);
    original.signer = "Some <!> &#_\"\" weird string";
    original.trusted = trusted;

    QString buffer;
    QXmlStreamWriter writer(&buffer);
    writer.writeStartDocument();
    KeeShareSettings::Certificate::serialize(writer, original, "Certificate");
    writer.writeEndDocument();
    QXmlStreamReader reader(buffer);
    KeeShareSettings::Certificate restored = KeeShareSettings::Certificate::deserialize(reader, "Certificate");

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
    KeeShareSettings::Key original;
    original.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Private, key);

    QString buffer;
    QXmlStreamWriter writer(&buffer);
    writer.writeStartDocument();
    KeeShareSettings::Key::serialize(writer, original, "Key");
    writer.writeEndDocument();
    QXmlStreamReader reader(buffer);
    KeeShareSettings::Key restored = KeeShareSettings::Key::deserialize(reader, "Key");

    QCOMPARE(restored.key, original.key);
    QCOMPARE(restored.sshKey().privateParts(), key.privateParts());
    QCOMPARE(restored.sshKey().type(), key.type());
}

void TestSharing::testSettingsSerialization()
{

    QFETCH(bool, importing);
    QFETCH(bool, exporting);
    QFETCH(KeeShareSettings::Certificate, ownCertificate);
    QFETCH(KeeShareSettings::Key, ownKey);
    QFETCH(QList<KeeShareSettings::Certificate>, foreignCertificates);

    KeeShareSettings original;
    original.importing = importing;
    original.exporting = exporting;
    original.ownCertificate = ownCertificate;
    original.ownKey = ownKey;
    original.foreignCertificates = foreignCertificates;

    const QString serialized = KeeShareSettings::serialize(original);
    KeeShareSettings restored = KeeShareSettings::deserialize(serialized);

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
    KeeShareSettings::Certificate certificate0;
    certificate0.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Public, sshKey0);
    certificate0.signer = "Some <!> &#_\"\" weird string";
    certificate0.trusted = true;

    KeeShareSettings::Key key0;
    key0.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Private, sshKey0);

    const OpenSSHKey &sshKey1 = stubkey(1);
    KeeShareSettings::Certificate certificate1;
    certificate1.key = OpenSSHKey::serializeToBinary(OpenSSHKey::Public, sshKey1);
    certificate1.signer = "Another ";
    certificate1.trusted = true;

    QTest::addColumn<bool>("importing");
    QTest::addColumn<bool>("exporting");
    QTest::addColumn<KeeShareSettings::Certificate>("ownCertificate");
    QTest::addColumn<KeeShareSettings::Key>("ownKey");
    QTest::addColumn<QList<KeeShareSettings::Certificate>>("foreignCertificates");
    QTest::newRow("1") << false << false << KeeShareSettings::Certificate() << KeeShareSettings::Key() << QList<KeeShareSettings::Certificate>();
    QTest::newRow("2") << true << false << KeeShareSettings::Certificate() << KeeShareSettings::Key() << QList<KeeShareSettings::Certificate>();
    QTest::newRow("3") << true << true << KeeShareSettings::Certificate() << KeeShareSettings::Key() << QList<KeeShareSettings::Certificate>({ certificate0, certificate1 });
    QTest::newRow("4") << false << true << certificate0 << key0 << QList<KeeShareSettings::Certificate>();
    QTest::newRow("5") << false << false << certificate0 << key0 << QList<KeeShareSettings::Certificate>({ certificate1 });
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
