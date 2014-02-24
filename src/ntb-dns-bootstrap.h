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

#ifndef NTB_DNS_BOOTSTRAP_H
#define NTB_DNS_BOOTSTRAP_H

#include "ntb-netaddress.h"

typedef void
(* ntb_dns_bootstrap_func)(const struct ntb_netaddress *address,
                           void *user_data);

void
ntb_dns_bootstrap(ntb_dns_bootstrap_func callback,
                  void *user_data);

#endif /* NTB_DNS_BOOTSTRAP_H */
