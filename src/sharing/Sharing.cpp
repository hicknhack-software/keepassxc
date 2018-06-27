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

#include "Sharing.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/DatabaseIcons.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "crypto/ssh/OpenSSHKey.h"
#include "sharing/Signature.h"
#include "sharing/SharingObserver.h"

#include <QPainter>
#include <QPushButton>
#include <QMessageBox>

namespace {

static const QString KeeShareExt("KeeShareXC");
static const QChar KeeShareExt_Delimiter('|');

}

Sharing* Sharing::m_instance = nullptr;

Sharing* Sharing::instance()
{
    if (!m_instance) {
        qFatal("Race condition: instance wanted before it was initialized, this is a bug.");
    }

    return m_instance;
}

void Sharing::init(QObject* parent)
{
    Q_ASSERT( ! m_instance );
    m_instance = new Sharing(parent);
}


Sharing::Reference::Reference()
    : type(Type::Inactive)
    , uuid(Uuid::random())
{
}

bool Sharing::Reference::isNull() const
{
    return type == Inactive && path.isEmpty() && password.isEmpty();
}

bool Sharing::Reference::isActive() const
{
    return type != Inactive && !path.isEmpty();
}

bool Sharing::Reference::isExporting() const
{
    return (type & ExportTo) != 0 && !path.isEmpty();
}

bool Sharing::Reference::isImporting() const
{
    return (type & ImportFrom) != 0 && !path.isEmpty();
}

bool Sharing::Reference::operator<(const Reference& other) const
{
    if (type != other.type) {
        return type < other.type;
    }
    return path < other.path;
}

bool Sharing::Reference::operator==(const Reference& other) const
{
    return path == other.path && uuid == other.uuid && password == other.password && type == other.type;
}

QString Sharing::Reference::serialize(const Reference &reference)
{
    const QStringList raw = QStringList()
            << QString::number(static_cast<int>(reference.type))
            << reference.uuid.toHex()
            << reference.path.toLatin1().toBase64()
            << reference.password.toLatin1().toBase64();
    return raw.join(KeeShareExt_Delimiter);
}

Sharing::Reference Sharing::Reference::deserialize(const QString &raw)
{
    Reference reference;

    const auto parts = raw.split(KeeShareExt_Delimiter);
    if (parts.count() != 4) {
        return reference;
    }
    reference.type = static_cast<Type>(parts[0].toInt());
    reference.uuid = Uuid::fromHex(parts[1]);
    reference.path = QByteArray::fromBase64(parts[2].toLatin1());
    reference.password = QByteArray::fromBase64(parts[3].toLatin1());

    return reference;
}


bool Sharing::isEnabled(const Database* db, Type type)
{
    const SharingSettings settings = Sharing::settingsOf(db);
    return ((type & ImportFrom) != 0 && settings.importing)
            || ((type & ExportTo) != 0 && settings.exporting);
}

bool Sharing::isShared(const Group* group)
{
    return group->customData()->contains(KeeShareExt);
}

Sharing::Reference Sharing::referenceOf(const CustomData* customData)
{
    static const Reference s_emptyReference;
    if (!customData->contains(KeeShareExt)) {
        return s_emptyReference;
    }
    Reference reference = Reference::deserialize(customData->value(KeeShareExt));
    if( reference.isNull() ){
        qWarning("Invalid sharing reference detected - sharing disabled");
        return s_emptyReference;
    }
    return reference;
}

SharingSettings Sharing::settingsOf(const Database *database)
{
    Q_ASSERT(database);
    const auto* meta = database->metadata();
    const auto* customData = meta->customData();
    return SharingSettings::deserialize(customData->value(KeeShareExt));
}

void Sharing::setReferenceTo(CustomData* customData, const Reference& reference)
{
    if (reference.isNull()) {
        customData->remove(KeeShareExt);
        return;
    }
    if (customData->contains(KeeShareExt)) {
        customData->set(KeeShareExt, Reference::serialize(reference));
    }
    customData->set(KeeShareExt, Reference::serialize(reference));
}

void Sharing::setSettingsTo(Database *database, const SharingSettings &settings)
{
    Q_ASSERT( database );
    auto* metadata = database->metadata();
    auto* customData = metadata->customData();
    customData->set(KeeShareExt, SharingSettings::serialize(settings));
}

QPixmap Sharing::indicatorBadge(const Group* group, QPixmap pixmap)
{
    if (!isShared(group)) {
        return pixmap;
    }
    const Reference reference = referenceOf(group->customData());
    const bool enabled = isEnabled(group->database(), reference.type);
    const QPixmap badge = enabled ? databaseIcons()->iconPixmap(DatabaseIcons::SharedIconIndex)
                                  : databaseIcons()->iconPixmap(DatabaseIcons::UnsharedIconIndex);
    QImage canvas = pixmap.toImage();
    const QRectF target(canvas.width() * 0.4, canvas.height() * 0.4, canvas.width() * 0.6, canvas.height() * 0.6);
    QPainter painter(&canvas);
    painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
    painter.drawPixmap(target, badge, badge.rect());
    pixmap.convertFromImage(canvas);
    return pixmap;
}

QString Sharing::referenceTypeLabel(const Reference& reference)
{
    switch (reference.type) {
    case Sharing::Inactive:
        return tr("Disabled share");
    case Sharing::ImportFrom:
        return tr("Import from");
    case Sharing::ExportTo:
        return tr("Export to");
    case Sharing::SynchronizeWith:
        return tr("Synchronize with");
    }
    return "";
}

QString Sharing::indicatorSuffix(const Group* group, const QString& text)
{
    Q_UNUSED(group);
    return text;
    //    if (!isShared(group)) {
    //        return text;
    //    }
    //    const Reference reference = referenceOf(group->customData());
    //    return reference.isActive()
    //               ? tr("%1 [share active]", "Template for name with active sharing annotation").arg(text)
    //               : tr("%1 [share inactive]", "Template for name with inactive sharing annotation").arg(text);
}

void Sharing::connectDatabase(Database *newDb, Database *oldDb)
{
    if( oldDb && m_observersByDatabase.contains(oldDb) ){
        QPointer<SharingObserver> observer = m_observersByDatabase.take(oldDb);
        if( observer ){
            delete observer;
        }
    }

    if( newDb && !m_observersByDatabase.contains(newDb) ){
        QPointer<SharingObserver> observer(new SharingObserver(newDb, newDb));
        m_observersByDatabase[newDb] = observer;
        connect(observer.data(), SIGNAL(sharingMessage(QString, MessageWidget::MessageType))
                ,this, SLOT(emitSharingMessage(QString, MessageWidget::MessageType)));
    }
}

void Sharing::handleDatabaseOpened(Database *db)
{
    QPointer<SharingObserver> observer = m_observersByDatabase.value(db);
    if( observer ){
        observer->handleDatabaseOpened();
    }
}

void Sharing::handleDatabaseSaved(Database *db)
{
    QPointer<SharingObserver> observer = m_observersByDatabase.value(db);
    if( observer ){
        observer->handleDatabaseSaved();
    }
}

void Sharing::emitSharingMessage(const QString &message, KMessageWidget::MessageType type)
{
    QObject *observer = sender();
    Database* db = m_databasesByObserver.value(observer);
    if( db ){
        emit sharingMessage(db, message, type);
    }
}

void Sharing::handleDatabaseDeleted(QObject *db)
{
    auto observer = m_observersByDatabase.take(db);
    if( observer ){
        m_databasesByObserver.remove(observer);
    }
}

void Sharing::handleObserverDeleted(QObject *observer)
{
    auto database = m_databasesByObserver.take(observer);
    if( database ){
        m_observersByDatabase.remove(database);
    }
}

Sharing::Sharing(QObject *parent)
    : QObject(parent)
{

}
