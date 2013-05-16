/**
 * logging.h
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2013.
 */

#ifndef __logging_H
#define __logging_H

#ifndef LOG_ENTRIES
  #define LOG_ENTRIES 30
#endif // !LOG_ENTRIES

#ifndef LOG_ENTRY_SIZE
  #define LOG_ENTRY_SIZE 16
#endif // !LOG_ENTRIES

typedef unsigned char LogEntry[LOG_ENTRY_SIZE];

typedef struct {
  LogEntry *entry;
  LogEntry list[LOG_ENTRIES];
  unsigned char head;
} Log;

LogEntry *log_new_entry(Log *log);

LogEntry *log_get_entry(Log *log, unsigned char index);

#endif // __logging_H
