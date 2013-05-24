/**
 * logging.c
 *
 * This file is part of IRMAcard.
 *
 * IRMAcard is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IRMAcard is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IRMAcard. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) May 2013 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#include "logging.h"

LogEntry *log_new_entry(Log *log) {
  log->entry = &(log->list[log->head]);
  log->head = (log->head + 1) % LOG_ENTRIES;

  // FIXME: CLEAR this log entry.
  
  return log->entry;
}

LogEntry *log_get_entry(Log *log, unsigned char index) { 
  return &(log->list[(2*LOG_ENTRIES + log->head - 1 - (index % LOG_ENTRIES)) % LOG_ENTRIES]);
}
