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

#ifndef NTB_PUB_KEY_MAKER_H
#define NTB_PUB_KEY_MAKER_H

struct ntb_pub_key_maker;

struct ntb_pub_key_maker *
ntb_pub_key_maker_new(void);

/* Converts a private key into a public key. The public key data
 * includes the 0x04 prefix so the buffer must be
 * NTB_KEY_PUBLIC_SIZE+1 */

void
ntb_pub_key_maker_make(struct ntb_pub_key_maker *maker,
                       const uint8_t *private_key,
                       uint8_t *public_key);

void
ntb_pub_key_maker_free(struct ntb_pub_key_maker *maker);

#endif /* NTB_PUB_KEY_MAKER_H */
