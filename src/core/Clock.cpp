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
#include "Clock.h"

static const Clock* m_clock = nullptr;

QDateTime Clock::currentDateTimeUtc()
{
    return instance().currentDateTimeUtcImpl();
}

QDateTime Clock::currentDateTime()
{
    return instance().currentDateTimeImpl();
}

uint Clock::currentSecondsSinceEpoch()
{
    return instance().currentDateTimeImpl().toTime_t();
}

QDateTime Clock::serialized(const QDateTime& dateTime)
{
    auto time = dateTime.time();
    if (time.isValid() && time.msec() != 0) {
        return dateTime.addMSecs(-time.msec());
    }
    return dateTime;
}

QDateTime Clock::datetimeUtc(int year, int month, int day, int hour, int min, int second)
{
    return QDateTime(QDate(year, month, day), QTime(hour, min, second), Qt::UTC);
}

QDateTime Clock::datetime(int year, int month, int day, int hour, int min, int second)
{
    return QDateTime(QDate(year, month, day), QTime(hour, min, second), Qt::LocalTime);
}

QDateTime Clock::datetimeUtc(qint64 msecSinceEpoch)
{
    return QDateTime::fromMSecsSinceEpoch(msecSinceEpoch, Qt::UTC);
}

QDateTime Clock::datetime(qint64 msecSinceEpoch)
{
    return QDateTime::fromMSecsSinceEpoch(msecSinceEpoch, Qt::LocalTime);
}

QDateTime Clock::parse(const QString& text, Qt::DateFormat format)
{
    return QDateTime::fromString(text, format);
}

QDateTime Clock::parse(const QString& text, const QString& format)
{
    return QDateTime::fromString(text, format);
}

Clock::~Clock()
{
}

Clock::Clock()
{
}

QDateTime Clock::currentDateTimeUtcImpl() const
{
    return QDateTime::currentDateTimeUtc();
}

QDateTime Clock::currentDateTimeImpl() const
{
    return QDateTime::currentDateTime();
}

void Clock::resetInstance()
{
    if (m_clock) {
        delete m_clock;
    }
    m_clock = nullptr;
}

void Clock::setInstance(Clock* clock)
{
    if (m_clock) {
        delete m_clock;
    }
    m_clock = clock;
}

const Clock& Clock::instance()
{
    if (!m_clock) {
        m_clock = new Clock();
    }
    return *m_clock;
}
