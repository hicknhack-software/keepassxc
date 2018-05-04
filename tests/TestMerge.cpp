/*
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include "TestMerge.h"
#include "TestGlobal.h"
#include "stub/TestClock.h"

#include "core/Merger.h"
#include "core/Metadata.h"
#include "crypto/Crypto.h"

QTEST_GUILESS_MAIN(TestMerge)

namespace
{
    TimeInfo moveTime(TimeInfo timeInfo, int iYears, int iMonths, int iDays)
    {
        const QDateTime time = timeInfo.lastModificationTime();
        timeInfo.setLastModificationTime(time.addYears(iYears).addMonths(iMonths).addDays(iDays));
        timeInfo.setLocationChanged(time.addYears(iYears).addMonths(iMonths).addDays(iDays));
        return timeInfo;
    }

    TimeInfo modificationTime(TimeInfo timeInfo, int iYears, int iMonths, int iDays)
    {
        const QDateTime time = timeInfo.lastModificationTime();
        timeInfo.setLastModificationTime(time.addYears(iYears).addMonths(iMonths).addDays(iDays));
        return timeInfo;
    }

    Test::Clock* m_clock = nullptr;
}

void TestMerge::initTestCase()
{
    qRegisterMetaType<Entry*>("Entry*");
    qRegisterMetaType<Group*>("Group*");
    QVERIFY(Crypto::init());
}

void TestMerge::init()
{
    Q_ASSERT(m_clock == nullptr);
    m_clock = new Test::Clock(2010, 5, 5, 10, 30, 10);
    Test::Clock::setup(m_clock);
}

void TestMerge::cleanup()
{
    Test::Clock::teardown();
    m_clock = nullptr;
}

/**
 * Merge an existing database into a new one.
 * All the entries of the existing should end
 * up in the new one.
 */
void TestMerge::testMergeIntoNew()
{
    QScopedPointer<Database> dbSource(createTestDatabase());
    QScopedPointer<Database> dbDestination(new Database());

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QCOMPARE(dbDestination->rootGroup()->children().size(), 2);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().size(), 2);
    // Test for retention of history
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().isEmpty(), false);
}

/**
 * Merging when no changes occured should not
 * have any side effect.
 */
void TestMerge::testMergeNoChanges()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);
    QCOMPARE(dbSource->rootGroup()->entriesRecursive().size(), 2);

    m_clock->advanceSecond(1);

    Merger merger1(dbSource.data(), dbDestination.data());
    merger1.merge();

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);
    QCOMPARE(dbSource->rootGroup()->entriesRecursive().size(), 2);

    m_clock->advanceSecond(1);

    Merger merger2(dbSource.data(), dbDestination.data());
    merger2.merge();

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);
    QCOMPARE(dbSource->rootGroup()->entriesRecursive().size(), 2);
}

/**
 * If the entry is updated in the source database, the update
 * should propagate in the destination database.
 */
void TestMerge::testResolveConflictNewer()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    // sanity check
    QPointer<Group> groupSourceInitial = dbSource->rootGroup()->findChildByName("group1");
    QVERIFY(groupSourceInitial != nullptr);
    QCOMPARE(groupSourceInitial->entries().size(), 2);

    QPointer<Group> groupDestinationInitial = dbSource->rootGroup()->findChildByName("group1");
    QVERIFY(groupDestinationInitial != nullptr);
    QCOMPARE(groupDestinationInitial->entries().size(), 2);

    QPointer<Entry> entrySourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entrySourceInitial != nullptr);
    QVERIFY(entrySourceInitial->group() == groupSourceInitial);

    const TimeInfo entrySourceInitialTimeInfo = entrySourceInitial->timeInfo();
    const TimeInfo groupSourceInitialTimeInfo = groupSourceInitial->timeInfo();
    const TimeInfo groupDestinationInitialTimeInfo = groupDestinationInitial->timeInfo();

    // Make sure the two changes have a different timestamp.
    m_clock->advanceSecond(1);
    // make this entry newer than in destination db
    entrySourceInitial->beginUpdate();
    entrySourceInitial->setPassword("password");
    entrySourceInitial->endUpdate();

    const TimeInfo entrySourceUpdatedTimeInfo = entrySourceInitial->timeInfo();
    const TimeInfo groupSourceUpdatedTimeInfo = groupSourceInitial->timeInfo();

    QVERIFY(entrySourceInitialTimeInfo != entrySourceUpdatedTimeInfo);
    QVERIFY(groupSourceInitialTimeInfo == groupSourceUpdatedTimeInfo);
    QVERIFY(groupSourceInitialTimeInfo == groupDestinationInitialTimeInfo);

    // Make sure the merge changes have a different timestamp.
    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    // sanity check
    QPointer<Group> groupDestinationMerged = dbDestination->rootGroup()->findChildByName("group1");
    QVERIFY(groupDestinationMerged != nullptr);
    QCOMPARE(groupDestinationMerged->entries().size(), 2);
    QCOMPARE(groupDestinationMerged->timeInfo(), groupDestinationInitialTimeInfo);

    QPointer<Entry> entryDestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationMerged != nullptr);
    QVERIFY(entryDestinationMerged->group() != nullptr);
    QCOMPARE(entryDestinationMerged->password(), QString("password"));
    QCOMPARE(entryDestinationMerged->timeInfo(), entrySourceUpdatedTimeInfo);

    // When updating an entry, it should not end up in the
    // deleted objects.
    for (DeletedObject deletedObject : dbDestination->deletedObjects()) {
        QVERIFY(deletedObject.uuid != entryDestinationMerged->uuid());
    }
}

/**
 * If the entry is updated in the source database, and the
 * destination database after, the entry should remain the
 * same.
 */
void TestMerge::testResolveConflictOlder()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    // sanity check
    QPointer<Group> groupSourceInitial = dbSource->rootGroup()->findChildByName("group1");
    QVERIFY(groupSourceInitial != nullptr);
    QCOMPARE(groupSourceInitial->entries().size(), 2);

    QPointer<Group> groupDestinationInitial = dbDestination->rootGroup()->findChildByName("group1");
    QVERIFY(groupDestinationInitial != nullptr);
    QCOMPARE(groupSourceInitial->entries().size(), 2);

    QPointer<Entry> entrySourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entrySourceInitial != nullptr);
    QVERIFY(entrySourceInitial->group() == groupSourceInitial);

    const TimeInfo entrySourceInitialTimeInfo = entrySourceInitial->timeInfo();
    const TimeInfo groupSourceInitialTimeInfo = groupSourceInitial->timeInfo();
    const TimeInfo groupDestinationInitialTimeInfo = groupDestinationInitial->timeInfo();

    // Make sure the two changes have a different timestamp.
    m_clock->advanceSecond(1);
    // make this entry older than in destination db
    entrySourceInitial->beginUpdate();
    entrySourceInitial->setPassword("password1");
    entrySourceInitial->endUpdate();

    const TimeInfo entrySourceUpdatedOlderTimeInfo = entrySourceInitial->timeInfo();
    const TimeInfo groupSourceUpdatedOlderTimeInfo = groupSourceInitial->timeInfo();

    QPointer<Group> groupDestinationUpdated = dbDestination->rootGroup()->findChildByName("group1");
    QVERIFY(groupDestinationUpdated != nullptr);
    QCOMPARE(groupDestinationUpdated->entries().size(), 2);
    QPointer<Entry> entryDestinationUpdated = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationUpdated != nullptr);
    QVERIFY(entryDestinationUpdated->group() == groupDestinationUpdated);

    // Make sure the two changes have a different timestamp.
    m_clock->advanceSecond(1);
    // make this entry newer than in source db
    entryDestinationUpdated->beginUpdate();
    entryDestinationUpdated->setPassword("password2");
    entryDestinationUpdated->endUpdate();

    const TimeInfo entryDestinationUpdatedNewerTimeInfo = entryDestinationUpdated->timeInfo();
    const TimeInfo groupDestinationUpdatedNewerTimeInfo = groupDestinationUpdated->timeInfo();
    QVERIFY(entrySourceUpdatedOlderTimeInfo != entrySourceInitialTimeInfo);
    QVERIFY(entrySourceUpdatedOlderTimeInfo != entryDestinationUpdatedNewerTimeInfo);
    QVERIFY(groupSourceInitialTimeInfo == groupSourceUpdatedOlderTimeInfo);
    QVERIFY(groupDestinationInitialTimeInfo == groupDestinationUpdatedNewerTimeInfo);
    QVERIFY(groupSourceInitialTimeInfo == groupDestinationInitialTimeInfo);

    // Make sure the merge changes have a different timestamp.
    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    // sanity check
    QPointer<Group> groupDestinationMerged = dbDestination->rootGroup()->findChildByName("group1");
    QVERIFY(groupDestinationMerged != nullptr);
    QCOMPARE(groupDestinationMerged->entries().size(), 2);
    QCOMPARE(groupDestinationMerged->timeInfo(), groupDestinationUpdatedNewerTimeInfo);

    QPointer<Entry> entryDestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationMerged != nullptr);
    QCOMPARE(entryDestinationMerged->password(), QString("password2"));
    QCOMPARE(entryDestinationMerged->timeInfo(), entryDestinationUpdatedNewerTimeInfo);

    // When updating an entry, it should not end up in the
    // deleted objects.
    for (DeletedObject deletedObject : dbDestination->deletedObjects()) {
        QVERIFY(deletedObject.uuid != entryDestinationMerged->uuid());
    }
}

/**
 * Tests the KeepBoth merge mode.
 */
void TestMerge::testResolveConflictKeepBoth()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneIncludeHistory, Group::CloneIncludeEntries));

    // sanity check
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().size(), 2);

    // make this entry newer than in original db
    QPointer<Entry> updatedDestinationEntry = dbDestination->rootGroup()->children().at(0)->entries().at(0);
    const TimeInfo initialEntryTimeInfo = updatedDestinationEntry->timeInfo();
    const TimeInfo updatedEntryTimeInfo = modificationTime(initialEntryTimeInfo, 1, 0, 0);

    updatedDestinationEntry->setTimeInfo(updatedEntryTimeInfo);

    dbDestination->rootGroup()->setMergeMode(Group::MergeMode::KeepBoth);

    // Make sure the merge changes have a different timestamp.
    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    // one entry is duplicated because of mode
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().size(), 3);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().isEmpty(), false);
    // the older entry was merged from the other db as last in the group
    QPointer<Entry> newerEntry = dbDestination->rootGroup()->children().at(0)->entries().at(0);
    QPointer<Entry> olderEntry = dbDestination->rootGroup()->children().at(0)->entries().at(2);
    QVERIFY(newerEntry->title() == olderEntry->title());
    QVERIFY2(!newerEntry->attributes()->hasKey("merged"), "newer entry is not marked with an attribute \"merged\"");
    QVERIFY2(olderEntry->attributes()->hasKey("merged"), "older entry is marked with an attribute \"merged\"");
    QCOMPARE(olderEntry->historyItems().isEmpty(), false);
    QCOMPARE(newerEntry->timeInfo(), updatedEntryTimeInfo);
    // TODO HNH: this may be subject to discussions since the entry itself is newer but represents an older one
    // QCOMPARE(olderEntry->timeInfo(), initialEntryTimeInfo);
    QVERIFY2(olderEntry->uuid().toHex() != updatedDestinationEntry->uuid().toHex(),
             "KeepBoth should not reuse the UUIDs when cloning.");
}

/**
 * Tests the Synchronized merge mode.
 */
void TestMerge::testResolveConflictSynchronized()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());

    const TimeInfo initialTimeInfo = moveTime(TimeInfo(), -1, -1, -1);
    Entry* deletedEntry1 = new Entry();
    deletedEntry1->beginUpdate();
    deletedEntry1->setUuid(Uuid::random());
    deletedEntry1->setGroup(dbDestination->rootGroup());
    deletedEntry1->setTitle("deletedDestination");
    deletedEntry1->setTimeInfo(initialTimeInfo);
    deletedEntry1->endUpdate();
    Entry* deletedEntry2 = new Entry();
    deletedEntry2->beginUpdate();
    deletedEntry2->setUuid(Uuid::random());
    deletedEntry2->setGroup(dbDestination->rootGroup());
    deletedEntry2->setTitle("deletedSource");
    deletedEntry2->setTimeInfo(initialTimeInfo);
    deletedEntry2->endUpdate();

    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneIncludeHistory, Group::CloneIncludeEntries));

    // sanity check
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().size(), 2);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().count(), 1);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(1)->historyItems().count(), 1);
    QCOMPARE(dbSource->rootGroup()->children().at(0)->entries().size(), 2);
    QCOMPARE(dbSource->rootGroup()->children().at(0)->entries().at(0)->historyItems().count(), 1);
    QCOMPARE(dbSource->rootGroup()->children().at(0)->entries().at(1)->historyItems().count(), 1);

    // simulate some work in the dbs (manipulate the history)
    QPointer<Entry> destinationEntry0 = dbDestination->rootGroup()->children().at(0)->entries().at(0);
    QPointer<Entry> destinationEntry1 = dbDestination->rootGroup()->children().at(0)->entries().at(1);
    QPointer<Entry> sourceEntry0 = dbSource->rootGroup()->children().at(0)->entries().at(0);
    QPointer<Entry> sourceEntry1 = dbSource->rootGroup()->children().at(0)->entries().at(1);

    const TimeInfo commonHistoryRootTimeInfo = initialTimeInfo;

    destinationEntry0->historyItems().first()->setTimeInfo(commonHistoryRootTimeInfo);
    destinationEntry1->historyItems().first()->setTimeInfo(commonHistoryRootTimeInfo);
    sourceEntry0->historyItems().at(0)->setTimeInfo(commonHistoryRootTimeInfo);
    sourceEntry1->historyItems().at(0)->setTimeInfo(commonHistoryRootTimeInfo);

    const TimeInfo commonHistoryChangeTimeInfo = moveTime(initialTimeInfo, 0, 0, 1);
    destinationEntry0->addHistoryItem(destinationEntry0->clone(Entry::CloneNoFlags));
    destinationEntry1->addHistoryItem(destinationEntry1->clone(Entry::CloneNoFlags));
    sourceEntry0->addHistoryItem(sourceEntry0->clone(Entry::CloneNoFlags));
    sourceEntry1->addHistoryItem(sourceEntry1->clone(Entry::CloneNoFlags));
    // sanity check
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().count(), 2);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(1)->historyItems().count(), 2);
    QCOMPARE(dbSource->rootGroup()->children().at(0)->entries().at(0)->historyItems().count(), 2);
    QCOMPARE(dbSource->rootGroup()->children().at(0)->entries().at(1)->historyItems().count(), 2);
    destinationEntry0->historyItems().at(1)->setTimeInfo(commonHistoryChangeTimeInfo);
    destinationEntry1->historyItems().at(1)->setTimeInfo(commonHistoryChangeTimeInfo);
    sourceEntry0->historyItems().at(1)->setTimeInfo(commonHistoryChangeTimeInfo);
    sourceEntry1->historyItems().at(1)->setTimeInfo(commonHistoryChangeTimeInfo);

    const TimeInfo differentEarlieTimeInfo = moveTime(initialTimeInfo, 0, 1, 1);
    const TimeInfo differentLaterTimeInfo = moveTime(initialTimeInfo, 1, 0, 1);
    destinationEntry0->setTimeInfo(differentLaterTimeInfo);
    destinationEntry1->setTimeInfo(differentEarlieTimeInfo);
    sourceEntry0->setTimeInfo(differentEarlieTimeInfo);
    sourceEntry1->setTimeInfo(differentLaterTimeInfo);

    QPointer<Entry> deletedEntryDestination = dbDestination->rootGroup()->findEntry("deletedDestination");
    dbDestination->recycleEntry(deletedEntryDestination);
    QPointer<Entry> deletedEntrySource = dbSource->rootGroup()->findEntry("deletedSource");
    dbSource->recycleEntry(deletedEntrySource);

    Entry* destinationEntrySingle = new Entry();
    destinationEntrySingle->beginUpdate();
    destinationEntrySingle->setUuid(Uuid::random());
    destinationEntrySingle->setGroup(dbDestination->rootGroup()->children().at(1));
    destinationEntrySingle->setTitle("entryDestination");
    destinationEntrySingle->endUpdate();

    Entry* sourceEntrySingle = new Entry();
    sourceEntrySingle->beginUpdate();
    sourceEntrySingle->setUuid(Uuid::random());
    sourceEntrySingle->setGroup(dbSource->rootGroup()->children().at(1));
    sourceEntrySingle->setTitle("entrySource");
    sourceEntrySingle->endUpdate();

    dbDestination->rootGroup()->setMergeMode(Group::MergeMode::Synchronize);

    // Make sure the merge changes have a different timestamp.
    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    // Stategies to synchronize from KeePass2
    //   - entries are equal - do nothing
    //   - one entry is older than the other - create an history item for this entry - sort items for both entries by
    //   changetime and order them accordingly
    QCOMPARE(dbDestination->rootGroup()->entries().size(), 0);
    // Both databases contain their own generated recycleBin - just one is considered a real recycleBin, the other
    // exists as normal group
    QCOMPARE(dbDestination->metadata()->recycleBin()->entries().size(), 1);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().size(), 2);
    QCOMPARE(dbDestination->rootGroup()->children().at(1)->entries().size(), 2);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().count(), 3);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().at(0)->timeInfo(),
             commonHistoryRootTimeInfo);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().at(1)->timeInfo(),
             commonHistoryChangeTimeInfo);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(0)->historyItems().at(2)->timeInfo(),
             differentEarlieTimeInfo);
    QVERIFY(dbDestination->rootGroup()->children().at(0)->entries().at(0)->timeInfo().lastModificationTime()
            >= differentLaterTimeInfo.lastModificationTime());
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(1)->historyItems().count(), 3);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(1)->historyItems().at(0)->timeInfo(),
             commonHistoryRootTimeInfo);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(1)->historyItems().at(1)->timeInfo(),
             commonHistoryChangeTimeInfo);
    QCOMPARE(dbDestination->rootGroup()->children().at(0)->entries().at(1)->historyItems().at(2)->timeInfo(),
             differentEarlieTimeInfo);
    QVERIFY(dbDestination->rootGroup()->children().at(0)->entries().at(1)->timeInfo().lastModificationTime()
            >= differentLaterTimeInfo.lastModificationTime());
    QVERIFY(dbDestination->rootGroup()->findEntry("entryDestination"));
    QVERIFY(dbDestination->rootGroup()->findEntry("entrySource"));
}

/**
 * The location of an entry should be updated in the
 * destination database.
 */
void TestMerge::testMoveEntry()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    QPointer<Entry> entrySourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entrySourceInitial != nullptr);

    QPointer<Group> groupSourceInitial = dbSource->rootGroup()->findChildByName("group2");
    QVERIFY(groupSourceInitial != nullptr);

    // Make sure the two changes have a different timestamp.
    m_clock->advanceSecond(1);

    entrySourceInitial->setGroup(groupSourceInitial);
    QCOMPARE(entrySourceInitial->group()->name(), QString("group2"));

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QPointer<Entry> entryDestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationMerged != nullptr);
    QCOMPARE(entryDestinationMerged->group()->name(), QString("group2"));
    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);
}

/**
 * The location of an entry should be updated in the
 * destination database, but changes from the destination
 * database should be preserved.
 */
void TestMerge::testMoveEntryPreserveChanges()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    QPointer<Entry> entrySourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entrySourceInitial != nullptr);

    QPointer<Group> group2Source = dbSource->rootGroup()->findChildByName("group2");
    QVERIFY(group2Source != nullptr);

    m_clock->advanceSecond(1);

    entrySourceInitial->setGroup(group2Source);
    QCOMPARE(entrySourceInitial->group()->name(), QString("group2"));

    QPointer<Entry> entryDestinationInitial = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationInitial != nullptr);

    m_clock->advanceSecond(1);

    entryDestinationInitial->beginUpdate();
    entryDestinationInitial->setPassword("password");
    entryDestinationInitial->endUpdate();

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QPointer<Entry> entryDestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationMerged != nullptr);
    QCOMPARE(entryDestinationMerged->group()->name(), QString("group2"));
    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);
    QCOMPARE(entryDestinationMerged->password(), QString("password"));
}

void TestMerge::testCreateNewGroups()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    m_clock->advanceSecond(1);

    Group* groupSourceCreated = new Group();
    groupSourceCreated->setName("group3");
    groupSourceCreated->setUuid(Uuid::random());
    groupSourceCreated->setParent(dbSource->rootGroup());

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QPointer<Group> groupDestinationMerged = dbDestination->rootGroup()->findChildByName("group3");
    QVERIFY(groupDestinationMerged != nullptr);
    QCOMPARE(groupDestinationMerged->name(), QString("group3"));
}

void TestMerge::testMoveEntryIntoNewGroup()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    m_clock->advanceSecond(1);

    Group* groupSourceCreated = new Group();
    groupSourceCreated->setName("group3");
    groupSourceCreated->setUuid(Uuid::random());
    groupSourceCreated->setParent(dbSource->rootGroup());

    QPointer<Entry> entrySourceMoved = dbSource->rootGroup()->findEntry("entry1");
    entrySourceMoved->setGroup(groupSourceCreated);

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);

    QPointer<Group> groupDestinationMerged = dbDestination->rootGroup()->findChildByName("group3");
    QVERIFY(groupDestinationMerged != nullptr);
    QCOMPARE(groupDestinationMerged->name(), QString("group3"));
    QCOMPARE(groupDestinationMerged->entries().size(), 1);

    QPointer<Entry> entryDestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationMerged != nullptr);
    QCOMPARE(entryDestinationMerged->group()->name(), QString("group3"));
}

/**
 * Even though the entries' locations are no longer
 * the same, we will keep associating them.
 */
void TestMerge::testUpdateEntryDifferentLocation()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    Group* groupDestinationCreated = new Group();
    groupDestinationCreated->setName("group3");
    groupDestinationCreated->setUuid(Uuid::random());
    groupDestinationCreated->setParent(dbDestination->rootGroup());

    m_clock->advanceSecond(1);

    QPointer<Entry> entryDestinationMoved = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationMoved != nullptr);
    entryDestinationMoved->setGroup(groupDestinationCreated);
    Uuid uuidBeforeSyncing = entryDestinationMoved->uuid();
    QDateTime destinationLocationChanged = entryDestinationMoved->timeInfo().locationChanged();

    // Change the entry in the source db.
    m_clock->advanceSecond(1);

    QPointer<Entry> entrySourceMoved = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entrySourceMoved != nullptr);
    entrySourceMoved->beginUpdate();
    entrySourceMoved->setUsername("username");
    entrySourceMoved->endUpdate();
    QDateTime sourceLocationChanged = entrySourceMoved->timeInfo().locationChanged();

    QVERIFY(destinationLocationChanged > sourceLocationChanged);

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);

    QPointer<Entry> entryDestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entryDestinationMerged != nullptr);
    QVERIFY(entryDestinationMerged->group() != nullptr);
    QCOMPARE(entryDestinationMerged->username(), QString("username"));
    QCOMPARE(entryDestinationMerged->group()->name(), QString("group3"));
    QCOMPARE(uuidBeforeSyncing, entryDestinationMerged->uuid());
    // default merge strategie is KeepNewer - therefore the older location is used!
    QCOMPARE(entryDestinationMerged->timeInfo().locationChanged(), sourceLocationChanged);
}

/**
 * Groups should be updated using the uuids.
 */
void TestMerge::testUpdateGroup()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    m_clock->advanceSecond(1);

    QPointer<Group> groupSourceInitial = dbSource->rootGroup()->findChildByName("group2");
    groupSourceInitial->setName("group2 renamed");
    groupSourceInitial->setNotes("updated notes");
    Uuid customIconId = Uuid::random();
    QImage customIcon;
    dbSource->metadata()->addCustomIcon(customIconId, customIcon);
    groupSourceInitial->setIcon(customIconId);

    QPointer<Entry> entrySourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entrySourceInitial != nullptr);
    entrySourceInitial->setGroup(groupSourceInitial);
    entrySourceInitial->setTitle("entry1 renamed");
    Uuid uuidBeforeSyncing = entrySourceInitial->uuid();

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);

    QPointer<Entry> entryDestinationMerged = dbDestination->rootGroup()->findEntry("entry1 renamed");
    QVERIFY(entryDestinationMerged != nullptr);
    QVERIFY(entryDestinationMerged->group() != nullptr);
    QCOMPARE(entryDestinationMerged->group()->name(), QString("group2 renamed"));
    QCOMPARE(uuidBeforeSyncing, entryDestinationMerged->uuid());

    QPointer<Group> groupMerged = dbDestination->rootGroup()->findChildByName("group2 renamed");
    QCOMPARE(groupMerged->notes(), QString("updated notes"));
    QCOMPARE(groupMerged->iconUuid(), customIconId);
}

void TestMerge::testUpdateGroupLocation()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    Group* group3DestinationCreated = new Group();
    Uuid group3Uuid = Uuid::random();
    group3DestinationCreated->setUuid(group3Uuid);
    group3DestinationCreated->setName("group3");
    group3DestinationCreated->setParent(dbDestination->rootGroup()->findChildByName("group1"));

    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    // Sanity check
    QPointer<Group> group3SourceInitial = dbSource->rootGroup()->findGroupByUuid(group3Uuid);
    QVERIFY(group3DestinationCreated != nullptr);

    QDateTime initialLocationChanged = group3SourceInitial->timeInfo().locationChanged();

    m_clock->advanceSecond(1);

    QPointer<Group> group3SourceMoved = dbSource->rootGroup()->findGroupByUuid(group3Uuid);
    QVERIFY(group3SourceMoved != nullptr);
    group3SourceMoved->setParent(dbSource->rootGroup()->findChildByName("group2"));

    QDateTime movedLocaltionChanged = group3SourceMoved->timeInfo().locationChanged();
    QVERIFY(initialLocationChanged < movedLocaltionChanged);

    m_clock->advanceSecond(1);

    Merger merger1(dbSource.data(), dbDestination.data());
    merger1.merge();

    QPointer<Group> group3DestinationMerged1 = dbDestination->rootGroup()->findGroupByUuid(group3Uuid);
    QVERIFY(group3DestinationMerged1 != nullptr);
    QCOMPARE(group3DestinationMerged1->parent(), dbDestination->rootGroup()->findChildByName("group2"));
    QCOMPARE(group3DestinationMerged1->timeInfo().locationChanged(), movedLocaltionChanged);

    m_clock->advanceSecond(1);

    Merger merger2(dbSource.data(), dbDestination.data());
    merger2.merge();

    QPointer<Group> group3DestinationMerged2 = dbDestination->rootGroup()->findGroupByUuid(group3Uuid);
    QVERIFY(group3DestinationMerged2 != nullptr);
    QCOMPARE(group3DestinationMerged2->parent(), dbDestination->rootGroup()->findChildByName("group2"));
    QCOMPARE(group3DestinationMerged1->timeInfo().locationChanged(), movedLocaltionChanged);
}

/**
 * The first merge should create new entries, the
 * second should only sync them, since they have
 * been created with the same UUIDs.
 */
void TestMerge::testMergeAndSync()
{
    QScopedPointer<Database> dbDestination(new Database());
    QScopedPointer<Database> dbSource(createTestDatabase());

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 0);

    m_clock->advanceSecond(1);

    Merger merger1(dbSource.data(), dbDestination.data());
    merger1.merge();

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);

    m_clock->advanceSecond(1);

    Merger merger2(dbSource.data(), dbDestination.data());
    merger2.merge();

    // Still only 2 entries, since now we detect which are already present.
    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 2);
}

/**
 * Custom icons should be brought over when merging.
 */
void TestMerge::testMergeCustomIcons()
{
    QScopedPointer<Database> dbDestination(new Database());
    QScopedPointer<Database> dbSource(createTestDatabase());

    m_clock->advanceSecond(1);

    Uuid customIconId = Uuid::random();
    QImage customIcon;

    dbSource->metadata()->addCustomIcon(customIconId, customIcon);
    // Sanity check.
    QVERIFY(dbSource->metadata()->containsCustomIcon(customIconId));

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QVERIFY(dbDestination->metadata()->containsCustomIcon(customIconId));
}

void TestMerge::testMetadata()
{
    QSKIP("Sophisticated merging for Metadata not implemented");
    // TODO HNH: I think a merge of recycle bins would be nice since duplicating them
    //           is not realy a good solution - the one to use as final recycle bin
    //           is determined by the merge method - if only one has a bin, this one
    //           will be used - exception is the target has no recycle bin activated
}

void TestMerge::testDeletedEntry()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    m_clock->advanceSecond(1);

    QPointer<Entry> entry1SourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entry1SourceInitial != nullptr);
    Uuid entry1Uuid = entry1SourceInitial->uuid();
    delete entry1SourceInitial;
    QVERIFY(dbSource->containsDeletedObject(entry1Uuid));

    m_clock->advanceSecond(1);

    QPointer<Entry> entry2DestinationInitial = dbDestination->rootGroup()->findEntry("entry2");
    QVERIFY(entry2DestinationInitial != nullptr);
    Uuid entry2Uuid = entry2DestinationInitial->uuid();
    delete entry2DestinationInitial;
    QVERIFY(dbDestination->containsDeletedObject(entry2Uuid));

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QPointer<Entry> entry1DestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(!entry1DestinationMerged);
    QVERIFY(dbDestination->containsDeletedObject(entry1Uuid));
    QPointer<Entry> entry2DestinationMerged = dbDestination->rootGroup()->findEntry("entry2");
    QVERIFY(!entry2DestinationMerged);
    QVERIFY(dbDestination->containsDeletedObject(entry2Uuid));

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 0);
}

void TestMerge::testDeletedGroup()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    m_clock->advanceSecond(1);

    QPointer<Group> group2DestinationInitial = dbDestination->rootGroup()->findChildByName("group2");
    QVERIFY(group2DestinationInitial != nullptr);
    Entry* entry3DestinationCreated = new Entry();
    entry3DestinationCreated->beginUpdate();
    entry3DestinationCreated->setUuid(Uuid::random());
    entry3DestinationCreated->setGroup(group2DestinationInitial);
    entry3DestinationCreated->setTitle("entry3");
    entry3DestinationCreated->endUpdate();

    m_clock->advanceSecond(1);

    QPointer<Group> group1SourceInitial = dbSource->rootGroup()->findChildByName("group1");
    QVERIFY(group1SourceInitial != nullptr);
    QPointer<Entry> entry1SourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entry1SourceInitial != nullptr);
    QPointer<Entry> entry2SourceInitial = dbSource->rootGroup()->findEntry("entry2");
    QVERIFY(entry2SourceInitial != nullptr);
    Uuid group1Uuid = group1SourceInitial->uuid();
    Uuid entry1Uuid = entry1SourceInitial->uuid();
    Uuid entry2Uuid = entry2SourceInitial->uuid();
    delete group1SourceInitial;
    QVERIFY(dbSource->containsDeletedObject(group1Uuid));
    QVERIFY(dbSource->containsDeletedObject(entry1Uuid));
    QVERIFY(dbSource->containsDeletedObject(entry2Uuid));

    m_clock->advanceSecond(1);

    QPointer<Group> group2SourceInitial = dbSource->rootGroup()->findChildByName("group2");
    QVERIFY(group2SourceInitial != nullptr);
    Uuid group2Uuid = group2SourceInitial->uuid();
    delete group2SourceInitial;
    QVERIFY(dbSource->containsDeletedObject(group2Uuid));

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QVERIFY(dbDestination->containsDeletedObject(group1Uuid));
    QVERIFY(dbDestination->containsDeletedObject(entry1Uuid));
    QVERIFY(dbDestination->containsDeletedObject(entry2Uuid));
    QVERIFY(!dbDestination->containsDeletedObject(group2Uuid));

    QPointer<Entry> entry1DestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(!entry1DestinationMerged);
    QPointer<Entry> entry2DestinationMerged = dbDestination->rootGroup()->findEntry("entry2");
    QVERIFY(!entry2DestinationMerged);
    QPointer<Entry> entry3DestinationMerged = dbDestination->rootGroup()->findEntry("entry3");
    QVERIFY(entry3DestinationMerged);
    QPointer<Group> group1DestinationMerged = dbDestination->rootGroup()->findChildByName("group1");
    QVERIFY(!group1DestinationMerged);
    QPointer<Group> group2DestinationMerged = dbDestination->rootGroup()->findChildByName("group2");
    QVERIFY(group2DestinationMerged);

    QCOMPARE(dbDestination->rootGroup()->entriesRecursive().size(), 1);
}

void TestMerge::testDeletedRevertedEntry()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    m_clock->advanceSecond(1);

    QPointer<Entry> entry1DestinationInitial = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entry1DestinationInitial != nullptr);
    Uuid entry1Uuid = entry1DestinationInitial->uuid();
    delete entry1DestinationInitial;
    QVERIFY(dbDestination->containsDeletedObject(entry1Uuid));

    m_clock->advanceSecond(1);

    QPointer<Entry> entry2SourceInitial = dbSource->rootGroup()->findEntry("entry2");
    QVERIFY(entry2SourceInitial != nullptr);
    Uuid entry2Uuid = entry2SourceInitial->uuid();
    delete entry2SourceInitial;
    QVERIFY(dbSource->containsDeletedObject(entry2Uuid));

    m_clock->advanceSecond(1);

    QPointer<Entry> entry1SourceInitial = dbSource->rootGroup()->findEntry("entry1");
    QVERIFY(entry1SourceInitial != nullptr);
    entry1SourceInitial->setNotes("Updated");

    QPointer<Entry> entry2DestinationInitial = dbDestination->rootGroup()->findEntry("entry2");
    QVERIFY(entry2DestinationInitial != nullptr);
    entry2DestinationInitial->setNotes("Updated");

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QVERIFY(!dbDestination->containsDeletedObject(entry1Uuid));
    QVERIFY(!dbDestination->containsDeletedObject(entry2Uuid));

    QPointer<Entry> entry1DestinationMerged = dbDestination->rootGroup()->findEntry("entry1");
    QVERIFY(entry1DestinationMerged != nullptr);
    QVERIFY(entry1DestinationMerged->notes() == "Updated");
    QPointer<Entry> entry2DestinationMerged = dbDestination->rootGroup()->findEntry("entry2");
    QVERIFY(entry2DestinationMerged != nullptr);
    QVERIFY(entry2DestinationMerged->notes() == "Updated");
}

void TestMerge::testDeletedRevertedGroup()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    m_clock->advanceSecond(1);

    QPointer<Group> group2SourceInitial = dbSource->rootGroup()->findChildByName("group2");
    QVERIFY(group2SourceInitial != nullptr);
    Uuid group2Uuid = group2SourceInitial->uuid();
    delete group2SourceInitial;
    QVERIFY(dbSource->containsDeletedObject(group2Uuid));

    m_clock->advanceSecond(1);

    QPointer<Group> group1DestinationInitial = dbDestination->rootGroup()->findChildByName("group1");
    QVERIFY(group1DestinationInitial != nullptr);
    Uuid group1Uuid = group1DestinationInitial->uuid();
    delete group1DestinationInitial;
    QVERIFY(dbDestination->containsDeletedObject(group1Uuid));

    m_clock->advanceSecond(1);

    QPointer<Group> group1SourceInitial = dbSource->rootGroup()->findChildByName("group1");
    QVERIFY(group1SourceInitial != nullptr);
    group1SourceInitial->setNotes("Updated");

    m_clock->advanceSecond(1);

    QPointer<Group> group2DestinationInitial = dbDestination->rootGroup()->findChildByName("group2");
    QVERIFY(group2DestinationInitial != nullptr);
    group2DestinationInitial->setNotes("Updated");

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    QVERIFY(!dbDestination->containsDeletedObject(group1Uuid));
    QVERIFY(!dbDestination->containsDeletedObject(group2Uuid));

    QPointer<Group> group1DestinationMerged = dbDestination->rootGroup()->findChildByName("group1");
    QVERIFY(group1DestinationMerged != nullptr);
    QVERIFY(group1DestinationMerged->notes() == "Updated");
    QPointer<Group> group2DestinationMerged = dbDestination->rootGroup()->findChildByName("group2");
    QVERIFY(group2DestinationMerged != nullptr);
    QVERIFY(group2DestinationMerged->notes() == "Updated");
}

/**
 * If the group is updated in the source database, and the
 * destination database after, the group should remain the
 * same.
 */
void TestMerge::testResolveGroupConflictOlder()
{
    QScopedPointer<Database> dbDestination(createTestDatabase());
    QScopedPointer<Database> dbSource(
        createTestDatabaseStructureClone(dbDestination.data(), Entry::CloneNoFlags, Group::CloneIncludeEntries));

    // sanity check
    QPointer<Group> groupSourceInitial = dbSource->rootGroup()->findChildByName("group1");
    QVERIFY(groupSourceInitial != nullptr);

    // Make sure the two changes have a different timestamp.
    m_clock->advanceSecond(1);

    groupSourceInitial->setName("group1 updated in source");

    // Make sure the two changes have a different timestamp.
    m_clock->advanceSecond(1);

    QPointer<Group> groupDestinationUpdated = dbDestination->rootGroup()->findChildByName("group1");
    groupDestinationUpdated->setName("group1 updated in destination");

    m_clock->advanceSecond(1);

    Merger merger(dbSource.data(), dbDestination.data());
    merger.merge();

    // sanity check
    QPointer<Group> groupDestinationMerged =
        dbDestination->rootGroup()->findChildByName("group1 updated in destination");
    QVERIFY(groupDestinationMerged != nullptr);
}

Database* TestMerge::createTestDatabase()
{
    Database* db = new Database();

    Group* group1 = new Group();
    group1->setName("group1");
    group1->setUuid(Uuid::random());

    Group* group2 = new Group();
    group2->setName("group2");
    group2->setUuid(Uuid::random());

    Entry* entry1 = new Entry();
    Entry* entry2 = new Entry();

    // Give Entry 1 a history
    entry1->beginUpdate();
    entry1->setGroup(group1);
    entry1->setUuid(Uuid::random());
    entry1->setTitle("entry1");
    entry1->endUpdate();

    // Give Entry 2 a history
    entry2->beginUpdate();
    entry2->setGroup(group1);
    entry2->setUuid(Uuid::random());
    entry2->setTitle("entry2");
    entry2->endUpdate();

    group1->setParent(db->rootGroup());
    group2->setParent(db->rootGroup());

    return db;
}

Database* TestMerge::createTestDatabaseStructureClone(Database* source, int entryFlags, int groupFlags)
{
    Database* db = new Database();
    // the old root group is deleted by QObject::parent relationship
    db->setRootGroup(source->rootGroup()->clone(static_cast<Entry::CloneFlag>(entryFlags),
                                                static_cast<Group::CloneFlag>(groupFlags)));
    return db;
}
