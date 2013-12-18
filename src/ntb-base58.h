/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013  Neil Roberts
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

#ifndef NTB_BASE58_H
#define NTB_BASE58_H

#include <stdint.h>
#include <stdlib.h>

#include "ntb-util.h"

size_t
ntb_base58_encode(const uint8_t *input,
                  size_t length,
                  char *output);

ssize_t
ntb_base58_decode(const char *input,
                  size_t input_length,
                  uint8_t *output,
                  size_t output_length);

#endif /* NTB_BASE58_H */
