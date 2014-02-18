/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NTB_SAVE_MESSAGE_H
#define NTB_SAVE_MESSAGE_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "ntb-blob.h"
#include "ntb-key.h"

void
ntb_save_message(time_t timestamp,
                 struct ntb_key *from_key,
                 const char *from_address,
                 struct ntb_key *to_key,
                 struct ntb_blob *blob,
                 FILE *out);

#endif /* NTB_SAVE_MESSAGE_H */
