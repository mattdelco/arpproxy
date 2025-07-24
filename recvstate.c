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

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arpproxy.h"

#include "recvstate.h"

void InitRecvState(RecvState *s) {
  s->recv_sock = -1;
  s->net_interface = NULL;
  for (int i = 0; i < ARRAYSIZE(s->other_interfaces); ++ i) {
    s->other_interfaces[i] = NULL;
  }
  s->num_other_interfaces = 0;
  memset(&(s->local_ip), 0, sizeof s->local_ip);
  memset(&(s->local_mac), 0, sizeof s->local_mac);
  struct sockaddr_ll device_sockaddr = {
    .sll_family = AF_PACKET,
    .sll_halen = MAC_LEN,
    .sll_protocol = htons(ETH_P_ARP),
  };
  memcpy(&(s->device_sockaddr), &device_sockaddr, sizeof device_sockaddr);
}

int RecvStateIsValid(const RecvState *s) {
  return s->recv_sock >= 0;
}

void FreeRecvState(RecvState *s) {
  if (s->recv_sock >= 0) {
    close(s->recv_sock);
    s->recv_sock = -1;
  }
  free(s->net_interface);
  s->net_interface = NULL;
  for (int i = 0; i < ARRAYSIZE(s->other_interfaces); ++ i) {
    free(s->other_interfaces[i]);
    s->other_interfaces[i] = NULL;
  }
}

// Scan all the adapters to find a NIC to use.  The name of all
// NICs is added to 'other_interfaces' (with count in
// 'num_other_interfaces'), while the name of the primary NIC
// selected is placed in 'net_interface' (and its IP address in
// 'local_ip'. Returns 1 on error, 0 on success.
static int ScanAdapters(RecvState *s) {
  struct ifaddrs *ifaces = NULL;

  // Scan all the NICs in the system to find one to use. We generally
  // expect to find at most 3 NICs in a Raspberry Pi (one wired,
  // one wireless, and one loopback).  We'll favor the wired if both
  // exist. We'll record the name of the NIC and also record the name
  // of the other NICs (it'll make it easier to detect when a new
  // [vs already known] NIC appears).
  int status = getifaddrs(&ifaces);
  if (status < 0) {
    dprintf(logfd, "Failed to get network interfaces: %u %u\n",
	    status, errno);
    return 1;
  }

  struct ifaddrs *iface = ifaces;
  while (iface) {
    if (debug) {
      dprintf(logfd, "Interface: %s with flags 0x%x\n",
	      iface->ifa_name, iface->ifa_flags);
    }
    // Skip the loopback interface.
    if (iface->ifa_flags & IFF_LOOPBACK) {
      if (debug) {
	dprintf(logfd, "Skipping loopback interface: %s flags 0x%x family %d\n",
		iface->ifa_name, iface->ifa_flags,
		((struct sockaddr_in *)iface->ifa_addr)->sin_family);
      }
      iface = iface->ifa_next;
      continue;
    }
    // Skip the interface if it's not IPv4.
    if (((struct sockaddr_in *)iface->ifa_addr)->sin_family != AF_INET) {
      if (debug) {
	// AF_PACKET=17, AF_INET6=10
	dprintf(logfd, "Skipping non-ipv4 interface: %s family %u\n",
		iface->ifa_name,  ((struct sockaddr_in *)iface->ifa_addr)->sin_family);
      }
      iface = iface->ifa_next;
      continue;
    }
    // Skip the interface if it's not up or doesn't have broadcast.
    if (!(iface->ifa_flags & IFF_UP) || !(iface->ifa_flags & IFF_BROADCAST)) {
      dprintf(logfd, "Interface %s with flags 0x%x family %u "
	      "doesn't have up broadcast interface\n",
	      iface->ifa_name, iface->ifa_flags,
	      ((struct sockaddr_in *)iface->ifa_addr)->sin_family);
      iface = iface->ifa_next;
      continue;
    }

    // The NIC is suitable, so add it to the list.
    if (s->num_other_interfaces < ARRAYSIZE(s->other_interfaces)) {
      s->other_interfaces[s->num_other_interfaces] = strdup(iface->ifa_name);
      if (!s->other_interfaces[s->num_other_interfaces]) {
	dprintf(logfd, "Failed to dup interface name: %s\n", iface->ifa_name);
      } else {
	++s->num_other_interfaces;
      }
    } else {
      dprintf(logfd, "ERROR: need to increase MAX_ALT_INTERFACES\n");
    }
    
    // If we haven't already picked a NIC (or we previously picked
    // wireless and now see a wired NIC) then select this NIC for use.
    // NOTE: in my experienced a wired USB NIC consumes more electical
    // power than a wireless NIC.
    if (!s->net_interface || (s->net_interface[0] == 'w' && iface->ifa_name[0] == 'e')) {
      if (debug) {
	dprintf(logfd, "Considering interface: %s with flags 0x%x\n",
		iface->ifa_name, iface->ifa_flags);
      }
      free(s->net_interface);
      s->net_interface = strdup(iface->ifa_name);
      if (!s->net_interface) {
	dprintf(logfd, "Failed to dup interface name: %s\n", iface->ifa_name);
      } else {
	// Record the IP address of the NIC.
	memcpy(&(s->local_ip), iface->ifa_addr, sizeof s->local_ip);
      }
    }
    iface = iface->ifa_next;
  }
  freeifaddrs(ifaces);

  return 0;
}

int FindAdapter(RecvState *s) {
  FreeRecvState(s);

  // Create a socket for receiving traffic.
  s->recv_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (s->recv_sock < 0) {
    dprintf(logfd, "Failed to allocate recv socket: %d\n", errno);
    return 1;
  }

  if (ScanAdapters(s)) {
    FreeRecvState(s);
    return 1;
  }

  time_t now = time(NULL);
  if (!s->net_interface) {
    dprintf(logfd, "Failed to determine a suitable interface (time is %ld)\n", now);
    FreeRecvState(s);
    return 1;
  }
  dprintf(logfd, "Using interface: %s (time is %ld)\n", s->net_interface, now);

  // Query the MAC address of the interface.

  int failed = 0;
  struct ifreq ifr = {0};
  snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", s->net_interface);

  int query_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (query_sock < 0) {
    dprintf(logfd, "Failed to allocate query socket: %d\n", errno);
    FreeRecvState(s);
    return 1;
  }
  if (ioctl(query_sock, SIOCGIFHWADDR, &ifr) < 0) {
    dprintf(logfd, "Failed to get source MAC address: %d\n", errno);
    failed = 1;
  }
  close(query_sock);
  if (failed) {
    FreeRecvState(s);
    return 1;
  }
  memcpy(&(s->local_mac), ifr.ifr_hwaddr.sa_data, sizeof s->local_mac);
  if (debug) {
    dprintf(logfd, "Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    s->local_mac[0], s->local_mac[1], s->local_mac[2],
	    s->local_mac[3], s->local_mac[4], s->local_mac[5]);
  }
  memcpy(&(s->device_sockaddr.sll_addr), &(s->local_mac), sizeof s->local_mac);

  // Lookup the interface number.
  if ((s->device_sockaddr.sll_ifindex = if_nametoindex(s->net_interface)) == 0) {
    dprintf(logfd, "Failed to obtain interface index for %s: %d\n",
            s->net_interface, errno);
    FreeRecvState(s);
    return 1;
  }
  if (debug) {
    dprintf(logfd, "Index for interface %s is %i\n", s->net_interface,
            s->device_sockaddr.sll_ifindex);
  }

  // Request promiscuous mode on the interface.
  struct packet_mreq request = {
    .mr_ifindex = s->device_sockaddr.sll_ifindex,
    .mr_type = PACKET_MR_PROMISC,
  };
  int status = setsockopt(s->recv_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
			  &request, sizeof request);
  if (status != 0) {
    dprintf(logfd, "Add membership failed: %d %d\n", status, errno);
    FreeRecvState(s);
    return 1;
  }
  return 0;
}
