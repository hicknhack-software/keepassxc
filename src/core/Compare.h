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

#ifndef KEEPASSXC_COMPARE_H
#define KEEPASSXC_COMPARE_H

#include <QDateTime>

#include "core/Clock.h"

enum CompareOption
{
    CompareDefault = 0,
    CompareRepresentsStatistic = 0x1,
    CompareSerializedTimestamps = 0x2,
    CompareIgnoreStatistics = 0x4,
    CompareIgnoreDisabled = 0x8,
    CompareIgnoreHistory = 0x10
};
Q_DECLARE_FLAGS(CompareOptions, CompareOption)
Q_DECLARE_OPERATORS_FOR_FLAGS(CompareOptions)

class QColor;

bool operator<(const QColor& lhs, const QColor& rhs);

template <typename Type> inline short compareGeneric(const Type& lhs, const Type& rhs, CompareOptions options)
{
    if (options.testFlag(CompareRepresentsStatistic) && options.testFlag(CompareIgnoreStatistics)) {
        return 0;
    }
    if (lhs != rhs) {
        return lhs < rhs ? -1 : +1;
    }
    return 0;
}

template <typename Type> inline short compare(const Type& lhs, const Type& rhs, CompareOptions options = CompareDefault)
{
    return compareGeneric(lhs, rhs, options);
}

template <> inline short compare(const QDateTime& lhs, const QDateTime& rhs, CompareOptions options)
{
    if (!options.testFlag(CompareSerializedTimestamps)) {
        return compareGeneric(lhs, rhs, options);
    }
    return compareGeneric(Clock::normalize(lhs), Clock::normalize(rhs), options);
}

template <typename Type>
inline short
compare(bool lhsEnabled, const Type& lhs, bool rhsEnabled, const Type& rhs, CompareOptions options = CompareDefault)
{
    short enabled = compareGeneric(lhsEnabled, rhsEnabled, options);
    if (enabled == 0) {
        if (!options.testFlag(CompareIgnoreDisabled) || (lhsEnabled && rhsEnabled)) {
            return compare(lhs, rhs, options);
        }
    }
    return enabled;
}

#endif // KEEPASSX_COMPARE_H
