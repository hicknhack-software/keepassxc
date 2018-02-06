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

#include "core/Merger.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Metadata.h"

static const Group::MergeMode ModeDefault = static_cast<Group::MergeMode>(-1);

Merger::Merger(const Database* sourceDb, Database* targetDb)
    : m_mode( ModeDefault )
{
    if (!sourceDb || !targetDb) {
        return;
    }

    m_context = MergeContext{
        sourceDb,
        targetDb,
        sourceDb->rootGroup(),
        targetDb->rootGroup(),
        sourceDb->rootGroup(),
        targetDb->rootGroup()
    };
}

Merger::Merger(const Group* sourceGroup, Group* targetGroup)
    : m_mode( ModeDefault )
{
    if (!sourceGroup || !targetGroup) {
        return;
    }

    m_context = MergeContext{
        sourceGroup->database(),
        targetGroup->database(),
        sourceGroup->database()->rootGroup(),
        targetGroup->database()->rootGroup(),
        sourceGroup,
        targetGroup
    };
}

void Merger::setForcedMergeMode(Group::MergeMode mode)
{
    m_mode = mode;
}

void Merger::resetForcedMergeMode()
{
    m_mode = ModeDefault;
}

bool Merger::merge()
{
    // Order of merge steps is important - it is possible that we
    // create some items before deleting them afterwards
    ChangeList changes;
    changes << mergeGroup(m_context);
    changes << mergeDeletions(m_context);
    changes << mergeMetadata(m_context);

    qDebug(">> CHANGES %s => %s: \n\t%s", qPrintable(m_context.m_sourceDb->metadata()->name()), qPrintable(m_context.m_targetDb->metadata()->name()), qPrintable(changes.join("\n\t")));

    if( !changes.isEmpty() ){
        m_context.m_targetDb->markAsModified();
        return true;
    }
    return false;
}

Merger::ChangeList Merger::mergeGroup(const MergeContext& context)
{
    ChangeList changes;
    // merge entries
    const QList<Entry*> sourceEntries = context.m_sourceGroup->entries();
    for (Entry* sourceEntry : sourceEntries) {
        Entry* targetEntry = context.m_targetRootGroup->findEntryByUuid(sourceEntry->uuid());
        if (!targetEntry) {
            changes << tr("Creating missing %1 [%2]").arg( sourceEntry->title()).arg(sourceEntry->uuid().toHex());
            // This entry does not exist at all. Create it.
            qDebug("New entry %s [%s] detected. Creating it.", qPrintable(sourceEntry->title()), qPrintable(sourceEntry->uuid().toHex()));
            targetEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
            const bool updateTimeinfo = targetEntry->canUpdateTimeinfo();
            targetEntry->setUpdateTimeinfo(false);
            targetEntry->setGroup(context.m_targetGroup);
            targetEntry->setUpdateTimeinfo(updateTimeinfo);
        } else {
            // Entry is already present in the database. Update it.
            bool locationChanged = targetEntry->timeInfo().locationChanged() < sourceEntry->timeInfo().locationChanged();
            if (locationChanged && targetEntry->group() != context.m_targetGroup ) {
                changes << tr("Relocating %1 [%2]").arg(sourceEntry->title()).arg(sourceEntry->uuid().toHex());
                const bool updateTimeinfo = targetEntry->canUpdateTimeinfo();
                targetEntry->setGroup(context.m_targetGroup);
                targetEntry->setUpdateTimeinfo(updateTimeinfo);
                qDebug("Location changed for entry %s [%s]. Updating it", qPrintable(targetEntry->title()), qPrintable(targetEntry->uuid().toHex()));
            }
            else {
                qDebug("Unifing entry %s [%s]. Updating it", qPrintable(targetEntry->title()), qPrintable(targetEntry->uuid().toHex()));
            }
            changes << resolveEntryConflict(context, sourceEntry, targetEntry);
        }
    }

    // merge groups recursively
    const QList<Group*> sourceChildGroups = context.m_sourceGroup->children();
    for (Group* sourceChildGroup : sourceChildGroups) {
        Group* targetChildGroup = context.m_targetRootGroup->findGroupByUuid(sourceChildGroup->uuid());
        if (!targetChildGroup) {
            changes << tr("Creating missing %1 [%2]").arg(sourceChildGroup->name()).arg(sourceChildGroup->uuid().toHex());
            qDebug("New group %s [%s] detected. Creating it.", qPrintable(sourceChildGroup->name()), qPrintable(sourceChildGroup->uuid().toHex()));
            targetChildGroup = sourceChildGroup->clone(Entry::CloneNoFlags, Group::CloneNoFlags);
            TimeInfo timeinfo = targetChildGroup->timeInfo();
            targetChildGroup->setParent(context.m_targetGroup);
            timeinfo.setLocationChanged(sourceChildGroup->timeInfo().locationChanged());
            targetChildGroup->setTimeInfo(timeinfo);
        } else {
            bool locationChanged = targetChildGroup->timeInfo().locationChanged() < sourceChildGroup->timeInfo().locationChanged();
            if (locationChanged && targetChildGroup->parent() != context.m_targetGroup ) {
                changes << tr("Relocating %1 [%2]").arg(sourceChildGroup->name()).arg(sourceChildGroup->uuid().toHex());
                TimeInfo timeinfo = targetChildGroup->timeInfo();
                targetChildGroup->setParent(context.m_targetGroup);
                timeinfo.setLocationChanged(sourceChildGroup->timeInfo().locationChanged());
                targetChildGroup->setTimeInfo(timeinfo);
                qDebug("Location changed for group %s [%s]. Updating it", qPrintable(targetChildGroup->name()), qPrintable(targetChildGroup->uuid().toHex()));
            }
            else {
                qDebug("Unifing group %s [%s]. Updating it", qPrintable(targetChildGroup->name()), qPrintable(targetChildGroup->uuid().toHex()));
            }
            changes << resolveGroupConflict(context, sourceChildGroup, targetChildGroup);
        }
        MergeContext subcontext {
            context.m_sourceDb,
            context.m_targetDb,
            context.m_sourceRootGroup,
            context.m_targetRootGroup,
            sourceChildGroup,
            targetChildGroup
        };
        changes << mergeGroup(subcontext);
    }
    return changes;
}

Merger::ChangeList Merger::resolveGroupConflict(const MergeContext& context, const Group* sourceChildGroup, Group* targetChildGroup)
{
    Q_UNUSED(context);
    ChangeList changes;

    const QDateTime timeExisting = targetChildGroup->timeInfo().lastModificationTime();
    const QDateTime timeOther = sourceChildGroup->timeInfo().lastModificationTime();

    // only if the other group is newer, update the existing one.
    if (timeExisting < timeOther) {
        changes << tr("Overwriting %1 [%2]").arg(sourceChildGroup->name()).arg(sourceChildGroup->uuid().toHex());
        qDebug("Updating group %s.", qPrintable(targetChildGroup->name()));
        targetChildGroup->setName(sourceChildGroup->name());
        targetChildGroup->setNotes(sourceChildGroup->notes());
        if (sourceChildGroup->iconNumber() == 0) {
          targetChildGroup->setIcon(sourceChildGroup->iconUuid());
        } else {
          targetChildGroup->setIcon(sourceChildGroup->iconNumber());
        }
        targetChildGroup->setExpiryTime(sourceChildGroup->timeInfo().expiryTime());
        // TODO CK: Update timestamps?
    }
    return changes;
}

bool Merger::markOlderEntry(Entry *entry)
{
    entry->attributes()->set(
                "merged",
                tr("older entry merged from database \"%1\"").arg(entry->group()->database()->metadata()->name()));
    return true;
}

Merger::ChangeList Merger::resolveEntryConflict(const MergeContext& context, const Entry* sourceEntry, Entry* targetEntry)
{
    ChangeList changes;
    const auto timeTarget = targetEntry->timeInfo().lastModificationTime();
    const auto timeSource = sourceEntry->timeInfo().lastModificationTime();

    Group::MergeMode mergeMode = m_mode == ModeDefault
            ? context.m_targetGroup->mergeMode()
            : m_mode;

    switch (mergeMode) {
    case Group::KeepBoth:
        // if one entry is newer, create a clone and add it to the group
        if (timeTarget > timeSource) {
            Entry* clonedEntry = sourceEntry->clone(Entry::CloneNewUuid | Entry::CloneIncludeHistory);
            bool updateTimeinfo = clonedEntry->canUpdateTimeinfo();
            clonedEntry->setUpdateTimeinfo(false);
            clonedEntry->setGroup(context.m_targetGroup);
            clonedEntry->setUpdateTimeinfo(updateTimeinfo);
            markOlderEntry(clonedEntry);
            changes << tr("Adding backup for older source %1 [%2]").arg(sourceEntry->title()).arg(sourceEntry->uuid().toHex());
        } else if (timeTarget < timeSource) {
            Entry* clonedEntry = sourceEntry->clone(Entry::CloneNewUuid | Entry::CloneIncludeHistory);
            const bool updateTimeinfo = clonedEntry->canUpdateTimeinfo();
            clonedEntry->setUpdateTimeinfo(false);
            clonedEntry->setGroup(context.m_targetGroup);
            clonedEntry->setUpdateTimeinfo(updateTimeinfo);
            markOlderEntry(targetEntry);
            changes << tr("Adding backup for older target %1 [%2]").arg(targetEntry->title()).arg(targetEntry->uuid().toHex());
        }
        break;

    case Group::KeepNewer:
        if (timeTarget < timeSource) {
            // only if other entry is newer, replace existing one
            Entry* clonedEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
            Group* currentGroup = targetEntry->group();
            qDebug("Updating entry %s.", qPrintable(targetEntry->title()));
            const bool entryUpdateTimeinfo = clonedEntry->canUpdateTimeinfo();
            const bool groupUpdateTimeinfo = currentGroup->canUpdateTimeinfo();
            currentGroup->setUpdateTimeinfo(false);
            clonedEntry->setUpdateTimeinfo(false);
            clonedEntry->setGroup(currentGroup);
            // most simple method to remove an item from DeletedObjects :(
            const QList<DeletedObject> deletions = currentGroup->database()->deletedObjects();
            delete targetEntry;
            currentGroup->database()->setDeletedObjects(deletions);
            clonedEntry->setUpdateTimeinfo(entryUpdateTimeinfo);
            currentGroup->setUpdateTimeinfo(groupUpdateTimeinfo);
            changes << tr("Overwriting %1 [%2]").arg(clonedEntry->title()).arg(clonedEntry->uuid().toHex());
        }
        break;

    case Group::KeepExisting:
        break;

    case Group::Synchronize:
        if (timeTarget < timeSource){
            Group* currentGroup = targetEntry->group();
            Entry* clonedEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
            qDebug("Merge %s/%s with alien on top under %s", qPrintable(targetEntry->title()), qPrintable(sourceEntry->title()), qPrintable(currentGroup->name()));
            const bool entryUpdateTimeinfo = clonedEntry->canUpdateTimeinfo();
            const bool groupUpdateTimeinfo = currentGroup->canUpdateTimeinfo();
            clonedEntry->setUpdateTimeinfo(false);
            currentGroup->setUpdateTimeinfo(false);
            clonedEntry->setGroup(currentGroup);
            mergeHistory( targetEntry, clonedEntry );
            changes << tr("Synchronizing from newer source %1 [%2]").arg(targetEntry->title()).arg(targetEntry->uuid().toHex());
            // TODO CK: MemoryLeak
            // most simple method to remove an item from DeletedObjects :(
            const QList<DeletedObject> deletions = currentGroup->database()->deletedObjects();
            delete targetEntry;
            clonedEntry->setUpdateTimeinfo(entryUpdateTimeinfo);
            currentGroup->setUpdateTimeinfo(groupUpdateTimeinfo);
            currentGroup->database()->setDeletedObjects(deletions);
        }
        else {
            qDebug("Merge %s/%s with local on top/under %s", qPrintable(targetEntry->title()), qPrintable(sourceEntry->title()), qPrintable(targetEntry->group()->name()));
            const bool entryUpdateTimeinfo = targetEntry->canUpdateTimeinfo();
            targetEntry->setUpdateTimeinfo(false);
            const bool changed = mergeHistory( sourceEntry, targetEntry );
            targetEntry->setUpdateTimeinfo(entryUpdateTimeinfo);
            if( changed ) {
                changes << tr("Synchronizing from older source %1 [%2]").arg(targetEntry->title()).arg(targetEntry->uuid().toHex());
            }
        }
        break;

    default:
        // do nothing
        break;
    }
    return changes;
}

bool Merger::mergeHistory(const Entry *sourceEntry, Entry* targetEntry)
{
    const auto targetHistoryItems = targetEntry->historyItems();
    const auto sourceHistoryItems = sourceEntry->historyItems();

    QMap<QDateTime, Entry*> merged;
    for (Entry* historyItem : targetHistoryItems) {
        const QDateTime modificationTime = historyItem->timeInfo().lastModificationTime();
        Q_ASSERT(! merged.contains( modificationTime) );
        merged[ modificationTime ] = historyItem->clone( Entry::CloneNoFlags );
    }
    for (Entry* historyItem : sourceHistoryItems) {
        // Items with same modification-time changes will be regarded as same (like KeePass2)
        const QDateTime modificationTime = historyItem->timeInfo().lastModificationTime();
        if( ! merged.contains( modificationTime ) ){
            merged[ modificationTime ] = historyItem->clone( Entry::CloneNoFlags );
        }
    }
    const QDateTime ownModificationTime = targetEntry->timeInfo().lastModificationTime();
    const QDateTime otherModificationTime = sourceEntry->timeInfo().lastModificationTime();
    if( ownModificationTime < otherModificationTime && ! merged.contains( ownModificationTime ) ){
        merged[ ownModificationTime ] = targetEntry->clone( Entry::CloneNoFlags );
    }
    if( ownModificationTime > otherModificationTime && ! merged.contains( otherModificationTime )){
        merged[ otherModificationTime ] = sourceEntry->clone( Entry::CloneNoFlags );
    }

    bool changed = false;
    const int maxItems = targetEntry->database()->metadata()->historyMaxItems();
    const auto updatedHistoryItems = merged.values();
    for (int i = 0; i < maxItems; ++i) {
        const Entry* oldEntry = targetHistoryItems.value( targetHistoryItems.count() - i);
        const Entry* newEntry = updatedHistoryItems.value( updatedHistoryItems.count() - i);
        if (!oldEntry && !newEntry) {
            continue;
        }
        if (oldEntry && newEntry && oldEntry->equals(newEntry)){
            continue;
        }
        changed = true;
        break;
    }
    if (!changed) {
        qDeleteAll(updatedHistoryItems);
        return false;
    }
    // We need to prevent any modification to the database since every change should be tracked either
    // in a clone history item or in the Entry itself
    const bool blockedSignals = targetEntry->blockSignals(true);
    targetEntry->removeHistoryItems(targetHistoryItems);
    for (Entry* historyItem : merged.values()) {
        Q_ASSERT(!historyItem->parent());
        targetEntry->addHistoryItem( historyItem );

    }
    targetEntry->truncateHistory();
    targetEntry->blockSignals(blockedSignals);
    return true;
}

Merger::ChangeList Merger::mergeDeletions(const MergeContext& context)
{
    ChangeList changes;
    const auto targetDeletions = context.m_targetDb->deletedObjects();
    const auto sourceDeletions = context.m_sourceDb->deletedObjects();

    QList<DeletedObject> deletions;
    QMap<Uuid, DeletedObject> mergedDeletions;
    QList<Entry*> entries;
    QList<Group*> groups;
    for (const auto& object : (targetDeletions + sourceDeletions)) {
        if( ! mergedDeletions.contains(object.uuid) ){
            mergedDeletions[object.uuid] = object;

            auto* entry = context.m_targetRootGroup->findEntryByUuid(object.uuid);
            if (entry) {
                qDebug("Check deletion of entry %s [%s]", qPrintable(entry->title()), qPrintable(entry->uuid().toHex()));
                entries << entry;
                continue;
            }
            auto* group = context.m_targetRootGroup->findGroupByUuid(object.uuid);
            if (group) {
                qDebug("Check deletion of group %s [%s]", qPrintable(group->name()), qPrintable(group->uuid().toHex()));
                groups << group;
                continue;
            }
            deletions << object;
            continue;
        }
        if (mergedDeletions[object.uuid].deletionTime > object.deletionTime ){
            mergedDeletions[object.uuid] = object;
        }
    }
    // TODO CK: I'm quite sure, that every merge operation and every deletion because of the
    //          merge leads to an update of the modification time, which it should not!
    //          normally, a merge should result in the most youngest modification time of
    //          both entries - possible exception is the synchronized merge - needs testing!!!!

    while (!entries.isEmpty()) {
        auto* entry = entries.takeFirst();
        const auto& object = mergedDeletions[entry->uuid()];
        if (entry->timeInfo().lastModificationTime() > object.deletionTime) {
            qDebug("Keep deleted entry %s [%s] due to more recent modification.", qPrintable(entry->title()), qPrintable(entry->uuid().toHex()));
            continue;
        }
        qDebug("Deleted entry %s [%s] detected. Dropping it.", qPrintable(entry->title()), qPrintable(entry->uuid().toHex()));
        deletions << object;
        Group* parentGroup = entry->group();
        if (parentGroup) {
            changes << tr("Deleting child %1 [%2]").arg(entry->title()).arg(entry->uuid().toHex());
            bool updateTimeinfo = parentGroup->canUpdateTimeinfo();
            parentGroup->setUpdateTimeinfo(false);
            delete entry;
            parentGroup->setUpdateTimeinfo(updateTimeinfo);
        }
        else {
            changes << tr("Deleting zombie %1 [%2]").arg(entry->title()).arg(entry->uuid().toHex());
            delete entry;
        }
    }

    while (!groups.isEmpty()) {
        auto* group = groups.takeFirst();
        if (group->children().toSet().intersects(groups.toSet())){
            // we need to finish all children before we are able to determine if the group can be removed
            groups << group;
            continue;
        }
        const auto& object = mergedDeletions[group->uuid()];
        if (group->timeInfo().lastModificationTime() > object.deletionTime) {
            qDebug("Keep deleted group %s [%s] due to more recent modification.", qPrintable(group->name()), qPrintable(group->uuid().toHex()));
            continue;
        }
        if (!group->entriesRecursive(false).isEmpty() || !group->groupsRecursive(false).isEmpty()) {
            qDebug("Keep deleted group %s [%s] due to contained entries or groups.", qPrintable(group->name()), qPrintable(group->uuid().toHex()));
            continue;
        }
        qDebug("Deleted group %s [%s] detected. Dropping it.", qPrintable(group->name()), qPrintable(group->uuid().toHex()));
        deletions << object;
        Group* parentGroup = group->parentGroup();
        if (parentGroup) {
            changes << tr("Deleting child %1 [%2]").arg(group->name()).arg(group->uuid().toHex());
            bool updateTimeinfo = parentGroup->canUpdateTimeinfo();
            parentGroup->setUpdateTimeinfo(false);
            delete group;
            parentGroup->setUpdateTimeinfo(updateTimeinfo);
        }
        else {
            changes << tr("Deleting zombie %1 [%2]").arg(group->name()).arg(group->uuid().toHex());
            delete group;
        }
    }
    // Put every deletion to the earliest date of deletion
    if (deletions != context.m_targetDb->deletedObjects()){
        changes << tr("Changed deleted objects");
    }
    context.m_targetDb->setDeletedObjects(deletions);
    return changes;
}

Merger::ChangeList Merger::mergeMetadata(const MergeContext& context)
{
    // TODO CK: missing handling of recycle bin, names, templates for groups and entries,
    //          public data (entries of newer dict override keys of older dict - ignoring
    //          their own age - it is enough if one entry of the whole dict is newer) => possible lost update
    // TODO CK: CustomData is merged with entries of the new customData overwrite entries
    //          of the older CustomData - the dict with the newest entry is considered
    //          newer regardless of the age of the other entries => possible lost update
    ChangeList changes;
    auto* sourceMetadata = context.m_sourceDb->metadata();
    auto* targetMetadata = context.m_targetDb->metadata();

    for (Uuid customIconId : sourceMetadata->customIcons().keys()) {
        QImage customIcon = sourceMetadata->customIcon(customIconId);
        if (!targetMetadata->containsCustomIcon(customIconId)) {
            qDebug("Adding custom icon %s to database.", qPrintable(customIconId.toHex()));
            targetMetadata->addCustomIcon(customIconId, customIcon);
            changes << tr("Adding missing icon %1").arg(customIconId.toHex());
        }
    }
    return changes;
}
