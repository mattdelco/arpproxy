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

#ifndef	_RECVSTATE_H_
#define	_RECVSTATE_H_

#define MAX_ALT_INTERFACES 10 // Maximum number of network interfaces to track

#include <linux/if_packet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// This is the main state for the program
typedef struct RecvState {
  // Socket for receiving ARP requests.
  int recv_sock;
  // Textual name of network interface. Used for logging and to favor wired.
  char *net_interface;
  // Names of other interfaces. Used to track what we've previously
  // seen (so we know when a new one appears).
  char *other_interfaces[MAX_ALT_INTERFACES];
  // Number of elements in 'other_interfaces'.
  int num_other_interfaces;
  // IPv4 address of interface.
  // Used to track changes and to populate ARP response.
  struct sockaddr_in local_ip;
  // MAC address of interface. Used to populate ARP response.
  uint8_t local_mac[MAC_LEN];
  // Interface to send on and request promiscuous mode.
  struct sockaddr_ll device_sockaddr;
  // IP address of the router for the interface.
  u_int8_t router[IP_LEN];
} RecvState;

// Initializes 'RecvState' struct to empty state.
void InitRecvState(RecvState *s);

// Indicates of state has a valid interface information (it might
// be invalid if there's no NICs or none of them are up).
int RecvStateIsValid(const RecvState *s);

// Frees the state in 'RecvState'. Struct must have previously
// been init by InitRecvState().
void FreeRecvState(RecvState *s);

// Clears out 'RecvState', finds an interface to use and populates
// 'RecvState' with information about the NIC(s) in the system.
int FindAdapter(RecvState *s);

#endif
