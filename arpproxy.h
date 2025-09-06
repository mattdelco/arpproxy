/*
 * Copyright 2025 Matthew Delco
 * 
 * This file is part of Arpproxy.
 * 
 * Arpproxy is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) anylater version.
 * 
 * Arpproxy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with Arpproxy. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef	_ARPPROXY_H_
#define	_ARPPROXY_H_

#include <linux/if_ether.h>
#include <netinet/ip.h>

#ifndef ARRAYSIZE
#define ARRAYSIZE(_x) (sizeof(_x)/sizeof((_x)[0]))
#endif
#ifndef MAX
#define MAX(_a, _b) ((_a) >= (_b) ? (_a) : (_b))
#endif

#define MAC_LEN       ETH_ALEN
#define IP_LEN        4
#define PROTO_LEN     ETH_TLEN
#define ETH_MAXPACKET (ETH_HLEN + IP_MAXPACKET)

#define DISABLE_SEND 0 /* set to 1 to disable responses */
#define FORCE_DEBUG 0 /* set to 1 to force on debug logging */

extern int debug;
extern int logfd;

extern void aplog(const char *restrict format, ...);

#endif
