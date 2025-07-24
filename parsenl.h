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

#ifndef _PARSENL_H_
#define _PARSENL_H_

#include <linux/netlink.h>
#include <unistd.h>

#include "arpproxy.h"

#include "recvstate.h"

// Sends a message to netlink to request routes.  We'll use
// the response (processed by CheckCanIgnore()) to determine
// the default gateway.
void SendRouteQuery(const RecvState *state, int nl);

// This function checks if a received rtnetlink message can be ignored (e.g.,
// hourly DHCP renews can trigger a new message).
// If we get a route message for the current NIC interface then 'state' will
// be updated with the IP address of that interface's default gateway.
//
// This probably needs to be adjusted for multi-homed systems, e.g., by also
// keeping track of the interfaces we're aware of but ignoring in favor of
// the one we're using.
int CheckCanIgnore(const RecvState *state, struct nlmsghdr *msg, ssize_t len);

#endif
