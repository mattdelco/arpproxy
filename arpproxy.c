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

#include <errno.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "arpproxy.h"

#include "recvstate.h"
#include "parsenl.h"

#define WAIT_PERIOD 10 /* 10 seconds */
#define WAIT_COUNT   3 /* sent if 3 or more times in 10 seconds */
#define DELAY_PERIOD 10 /* 10 seconds */

// State to track ARP requests for targets
typedef struct IpTarget {
  // IP address of target to proxy for.
  u_int8_t ip[IP_LEN];
  // Time when first request was seen.
  time_t first_seen;
  // Number of times we've seen a request since 'first_seen'
  uint32_t seen_count;
} IpTarget;

// Representation of ARP packet for IPv4 & Ethernet
typedef struct ArpHeader {
  uint16_t header_type;
  uint16_t proto_type;
  uint8_t  header_len;
  uint8_t  proto_len;
  uint16_t op_code;
  uint8_t  sender_mac[MAC_LEN];
  uint8_t  sender_ip[IP_LEN];
  uint8_t  target_mac[MAC_LEN];
  uint8_t  target_ip[IP_LEN];
} ArpHeader;

// List of machines to proxy ARP
// NOTE: MODIFY THE FOLLOWING TO MATCH THE IP ADDRESS OF
// YOUR SYNOLOGY NAS.
IpTarget targets[] = {
  {{192, 168, 100, 5} /* 192.168.100.5 */},
};

// State for logging
int debug = FORCE_DEBUG;
// File descriptor to log to (default is stdout)
int logfd = STDOUT_FILENO;

void UpdateSendBuffer(char *send_frame, RecvState *state);

int main(int argc, char *argv[]) {
  // command-line parameter count (value of parameters irrelevant):
  // 1 (i.e., no parameters) -> open debug file
  // 2 -> use stdout
  // 3 -> use stdout and debug
  if (argc == 1) {
    logfd = open("/tmp/arpproxy.txt", O_WRONLY | O_CREAT | O_APPEND,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (logfd < 0) {
      printf("Failed to open log file: %d %d\n", logfd, errno);
      logfd = STDOUT_FILENO;
    }
  } else {
    logfd = STDOUT_FILENO;
  }
  debug = argc > 2 || FORCE_DEBUG;

  {
    time_t now = time(NULL);
    aplog("Starting at time %ld\n", now);
  }

  // Construct a buffer for using with netlink.
  struct nlmsghdr buf[8192/sizeof(struct nlmsghdr)];
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof buf,
  };
  struct sockaddr_nl recv_addr = {0};
  struct msghdr msg = {
    .msg_name = &recv_addr,
    .msg_namelen = sizeof recv_addr,
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = NULL,
    .msg_controllen = 0,
    .msg_flags = 0,
  };

  // State used for receiving and processing received frames.
  RecvState recv_state;
  InitRecvState(&recv_state);

  // Buffer we receive into.
  char recv_frame[ETH_MAXPACKET] = {0};
  uint16_t *recv_proto = (uint16_t *)&(recv_frame[MAC_LEN+MAC_LEN]);
  ArpHeader *recv_arp = (ArpHeader *)&(recv_frame[ETH_HLEN]);

  // Buffer we send from.
  char send_frame[ETH_MAXPACKET] = {0};
  ArpHeader *send_arp = (ArpHeader *)&(send_frame[ETH_HLEN]);

  int status = 0; // used to get status of API calls.

  // If we're in debug mode then list the IPs we'll be proxying for.
  if (debug) {
    for (int i = 0; i < ARRAYSIZE(targets); ++i) {
      IpTarget *target = &(targets[i]);
      aplog("target: %u.%u.%u.%u\n",
	    target->ip[0], target->ip[1], target->ip[2], target->ip[3]);
    }
  }

  int send_sock = -1; // socket used to send replies.
  int nl = -1; // netlink socket.
  int timer = -1; // timerfd

  // Create a socket used to send replies.
  send_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (send_sock < 0) {
    aplog("Failed to allocate send socket (run as sudo?): %d\n", errno);
    goto exit;
  }

  // Create the netlink socket.  This is used to monitor for NIC changes and
  // get the default gateway's IP address.
  nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl < 0) {
    aplog("Failed to get netlink: %d %d\n", nl, errno);
    goto exit;
  }

  {
    struct sockaddr_nl bind_addr = {
      .nl_family = AF_NETLINK,
      .nl_groups = RTMGRP_IPV4_IFADDR,
    };
    status = bind(nl, (struct sockaddr *) &bind_addr, sizeof bind_addr);
    if (status < 0) {
      aplog("Failed to bind netlink: %d %d\n", status, errno);
      goto exit;
    }
  }

  // Craete a timerfd that's used to defer and delay (and rate-limit) certain actions.
  timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (timer < 0) {
    aplog("Failed to create timer: %d %d\n", timer, errno);
    goto exit;
  }  

  // Consgtruct the array we'll use with poll().
  struct pollfd poll_array[] = {
    {.fd = nl, .events = POLLIN},
    {.fd = timer, .events = POLLIN},
    // The receive socket might not be valid so should be placed last in the array.
    {.fd = recv_state.recv_sock, .events = POLLIN},
  };

  // Determine which NIC we'll use, then send a query for the NIC's default gateway.
  if (FindAdapter(&recv_state)) {
    aplog("Failed to find adapter at startup\n");
    // We won't exit but will wait for suitable adapter to appear.
  } else {
    SendRouteQuery(&recv_state, nl);
  }

  // Update which socket we'll want poll() to monitor for incoming frames,
  // and init the send buffer.
  poll_array[2].fd = recv_state.recv_sock;
  UpdateSendBuffer(&(send_frame[0]), &recv_state);

  if (debug) {
    aplog("Starting event loop\n");
  }

  for (;;) {
    // We'll typically check all events, but if there's not a NIC then
    // we won't have a receive socket to monitor.
    int num_events = ARRAYSIZE(poll_array);
    if (poll_array[num_events - 1].fd < 0) {
      --num_events;
    }
    for (int i = 0; i < num_events; ++i) {
      poll_array[i].revents = 0;
    }
    if (debug) {
      aplog("Waiting for an event\n");
    }
    int ready = poll(poll_array, num_events, -1 /* infinite wait */);
    if (ready < 0) {
      aplog("Failed to poll: %d %d\n", ready, errno);
      goto exit;
    }
    if (debug) {
      aplog("%d events are ready\n", ready);
    }

    // If we received a netlink message.
    if (poll_array[0].revents & POLLIN) {
      int can_ignore = 0;
      if (debug) {
	time_t now = time(NULL);
        aplog("Reading link event at %ld\n", now);
      }

      // Receive a message, and if successful also check to see
      // if we can ignore the message.
      ssize_t len = recvmsg(nl, &msg, MSG_DONTWAIT);
      if (len < 0) {
        aplog("Got error on link event wait: %ld %d\n", len, errno);
      } else {
        if (debug) {
          aplog("Got len %ld for link event\n", len);
        }
	can_ignore = CheckCanIgnore(&recv_state, &buf[0], len);
      }

      if (can_ignore) {
	if (debug) {
	  aplog("Ignoring link event\n");
	}
      } else {
	// If we can't ignore the message, then schedule a timer
	// callback that'll check the new NIC configuration. This is
	// to rate-limit respones for link flaps and also give the
	// OS time to get updated information from DHCP.

	struct itimerspec delay = {.it_value = {.tv_sec = DELAY_PERIOD}};
	int result = timerfd_settime(timer, 0, &delay, NULL);
	if (result < 0) {
	  aplog("Failed to schedule timer: %d %d\n", result, errno);
	  goto exit;
	} else {
	  if (debug) {
	    time_t now = time(NULL);
	    aplog("Scheduled timer at %ld\n", now);
	  }
	}
      }
    }

    // The timer fired, so check which NIC to use.
    if (poll_array[1].revents & POLLIN) {
      uint64_t firings = 0;
      if (debug) {
	time_t now = time(NULL);
        aplog("Timer event has fired at %ld\n", now);
      }
      ssize_t len = read(timer, &firings, sizeof firings);
      if (len < 0) {
        aplog("Failed to read from clock timer: %ld %d\n", len, errno);
        goto exit;
      }
      if (len != sizeof firings) {
        aplog("Read from clock timer got unexpected length: %ld %d\n", len, errno);
        goto exit;
      }
      if (debug) {
	time_t now = time(NULL);
	aplog("At %ld timer has fired %lu time(s)\n", now, firings);
      }
      if (FindAdapter(&recv_state)) {
	time_t now = time(NULL);
	aplog("Failed to find adapter, not exiting (time is %ld)\n", now);
      } else {
	// Now that we've got a NIC send a request to get the default gateway.
	SendRouteQuery(&recv_state, nl);
      }
      poll_array[2].fd = recv_state.recv_sock;
      UpdateSendBuffer(&(send_frame[0]), &recv_state);
      continue; // don't check the socket because it's probably changed
    }

    // Socket may have been closed just after something received.
    if (!(poll_array[2].revents & POLLIN) || recv_state.recv_sock < 0) {
      continue;
    }

    status = recv(recv_state.recv_sock, recv_frame, sizeof recv_frame, 0);
    if (status < 0) {
      aplog("Recv failed: %d %d\n", status, errno);
      break;
    }
    if (debug) {
      aplog("Received frame of length: %d\n", status);
    }

    // If frame isn't ARP then poll for the next frame.
    if (status < ETH_HLEN + sizeof(ArpHeader)) {
      aplog("Packet too short for ARP: %d\n", status);
      continue;
    }
    if (*recv_proto != htons(ETH_P_ARP)) {
      if (debug) {
	aplog("Didn't get arp\n");
      }
      continue;
    }

    if (debug) {
      time_t now = time(NULL);
      aplog("At %ld received arp: type 0x%x proto 0x%x hlen %u plen %u op %u, "
	    "smac %02x:%02x:%02x:%02x:%02x:%02x sip %u.%u.%u.%u "
	    "tmac %02x:%02x:%02x:%02x:%02x:%02x tip %u.%u.%u.%u\n",
	    now,
	    ntohs(recv_arp->header_type), ntohs(recv_arp->proto_type),
	    recv_arp->header_len, recv_arp->proto_len,
	    ntohs(recv_arp->op_code),
	    recv_arp->sender_mac[0], recv_arp->sender_mac[1], recv_arp->sender_mac[2],
	    recv_arp->sender_mac[3], recv_arp->sender_mac[4], recv_arp->sender_mac[5],
	    recv_arp->sender_ip[0], recv_arp->sender_ip[1],
	    recv_arp->sender_ip[2], recv_arp->sender_ip[3],
	    recv_arp->target_mac[0], recv_arp->target_mac[1], recv_arp->target_mac[2],
	    recv_arp->target_mac[3], recv_arp->target_mac[4], recv_arp->target_mac[5],
	    recv_arp->target_ip[0], recv_arp->target_ip[1],
	    recv_arp->target_ip[2], recv_arp->target_ip[3]);
    }

    // Verify ARP is for Ethernet and IPv4.
    if (recv_arp->header_type != htons(ARPHRD_ETHER) || recv_arp->proto_type != htons(ETH_P_IP) ||
        recv_arp->header_len != MAC_LEN || recv_arp->proto_len != IP_LEN) {
      aplog("Not an Ethernet ARP: type %u proto %u hlen %u plen %u\n", ntohs(recv_arp->header_type),
	    ntohs(recv_arp->proto_type), recv_arp->header_len, recv_arp->proto_len);
      continue;
    }

    // Verify this is an ARP request.
    if (recv_arp->op_code != htons(ARPOP_REQUEST)) {
      if (debug) {
        aplog("Not an arp request: %u\n", ntohs(recv_arp->op_code));
      }
      continue;
    } 

    // Only process ARPs that come from the default gateway.
    if (memcmp(recv_state.router, recv_arp->sender_ip, IP_LEN) == 0) {
      // Populate the router for dest Ethernet MAC and ARP target.
      memcpy(&(send_frame[0]), recv_arp->sender_mac, MAC_LEN);
      memcpy(&(send_arp->target_mac), recv_arp->sender_mac, MAC_LEN);
      memcpy(&(send_arp->target_ip), recv_arp->sender_ip, IP_LEN);
    } else {
      if (debug) {
	aplog("ARP didn't match a router\n");
      }
      continue;
    }

    // Check if the ARP is for one of the targets we're configured to proxy for.
    int target_count = 0;
    for (int i = 0; i < ARRAYSIZE(targets) && target_count == 0; ++i) {
      IpTarget *target = &(targets[i]);
      uint8_t zeros[MAC_LEN] = {0};
      if (memcmp(zeros, recv_arp->target_mac, sizeof zeros) != 0 ||
          memcmp(target->ip, recv_arp->target_ip, IP_LEN) != 0)	{
	continue;
      }

      // We'll only respond if there's been multiple attempts to ARP the
      // target in a limited duration of time.
      ++target_count;
      time_t now = time(NULL);
      if (now > target->first_seen + WAIT_PERIOD) {
	target->first_seen = now;
	target->seen_count = 1;
      } else {
	++target->seen_count;
      }

      if (target->seen_count < WAIT_COUNT) {
	aplog("Request for %u.%u.%u.%u only seen %u time(s) in %u seconds so far (time is %ld)\n",
	      target->ip[0], target->ip[1], target->ip[2], target->ip[3],
	      target->seen_count, WAIT_PERIOD, now);
	continue;
      }

      // Sufficient ARP queries have been seen, so send a reply.

      aplog("Request for %u.%u.%u.%u seen %u time(s) in %u seconds so sending reply (time is %ld)\n",
	    target->ip[0], target->ip[1], target->ip[2], target->ip[3],
	    target->seen_count, WAIT_PERIOD, now);

      // Populate the target for ARP sender (Broadcast MAC seem to be required
      // by Synology NASes for this to work).
      memset(&(send_arp->sender_mac), 0xFF, sizeof(send_arp->sender_mac));
      memcpy(&(send_arp->sender_ip), target->ip, sizeof(send_arp->sender_ip));
      if (debug) {
	aplog("Sender result: arp type 0x%x proto 0x%x hlen %u plen %u op %u, "
	      "smac %02x:%02x:%02x:%02x:%02x:%02x sip %u.%u.%u.%u "
	      "tmac %02x:%02x:%02x:%02x:%02x:%02x tip %u.%u.%u.%u\n",
	      ntohs(send_arp->header_type), ntohs(send_arp->proto_type),
	      send_arp->header_len, send_arp->proto_len,
	      ntohs(send_arp->op_code),
	      send_arp->sender_mac[0], send_arp->sender_mac[1], send_arp->sender_mac[2],
	      send_arp->sender_mac[3], send_arp->sender_mac[4], send_arp->sender_mac[5],
	      send_arp->sender_ip[0], send_arp->sender_ip[1],
	      send_arp->sender_ip[2], send_arp->sender_ip[3],
	      send_arp->target_mac[0], send_arp->target_mac[1], send_arp->target_mac[2],
	      send_arp->target_mac[3], send_arp->target_mac[4], send_arp->target_mac[5],
	      send_arp->target_ip[0], send_arp->target_ip[1],
	      send_arp->target_ip[2], send_arp->target_ip[3]);
      }
#if DISABLE_SEND
      int send_result = MAX(ETH_HLEN + sizeof(ArpHeader), 60);
      aplog("sendto() DISABLED, so not actually sent");
#else
      int send_result = sendto(send_sock, &send_frame, MAX(ETH_HLEN + sizeof(ArpHeader), 60),
			       0, (struct sockaddr *) &(recv_state.device_sockaddr),
			       sizeof recv_state.device_sockaddr);
#endif
      if (send_result <= 0) {
	aplog("sendto() failed: %d %d\n", send_result, errno);
      } else {
	time_t now = time(NULL);
	if (debug) {
	  aplog("Sent reply at %ld: dst %02x:%02x:%02x:%02x:%02x:%02x "
		"src %02x:%02x:%02x:%02x:%02x:%02x ethproto 0x%04x "
		"arp type 0x%x proto 0x%x hlen %u plen %u op %u, "
		"smac %02x:%02x:%02x:%02x:%02x:%02x sip %u.%u.%u.%u "
		"tmac %02x:%02x:%02x:%02x:%02x:%02x tip %u.%u.%u.%u\n",
		now,
		send_frame[0], send_frame[1], send_frame[2],
		send_frame[3], send_frame[4], send_frame[5],
		send_frame[6], send_frame[7], send_frame[8],
		send_frame[9], send_frame[10], send_frame[11],
		ntohs(*(uint16_t*)&(send_frame[12])),
		ntohs(send_arp->header_type), ntohs(send_arp->proto_type),
		send_arp->header_len, send_arp->proto_len,
		ntohs(send_arp->op_code),
		send_arp->sender_mac[0], send_arp->sender_mac[1], send_arp->sender_mac[2],
		send_arp->sender_mac[3], send_arp->sender_mac[4], send_arp->sender_mac[5],
		send_arp->sender_ip[0], send_arp->sender_ip[1],
		send_arp->sender_ip[2], send_arp->sender_ip[3],
		send_arp->target_mac[0], send_arp->target_mac[1], send_arp->target_mac[2],
		send_arp->target_mac[3], send_arp->target_mac[4], send_arp->target_mac[5],
		send_arp->target_ip[0], send_arp->target_ip[1],
		send_arp->target_ip[2], send_arp->target_ip[3]);
	} else {
	  aplog("Successfully sent arp reply for %u.%u.%u.%u to %u.%u.%u.%u at %ld\n",
		send_arp->sender_ip[0], send_arp->sender_ip[1],
		send_arp->sender_ip[2], send_arp->sender_ip[3],
		send_arp->target_ip[0], send_arp->target_ip[1],
		send_arp->target_ip[2], send_arp->target_ip[3],
		now);
	}
      }
    }
    if (target_count < 1) {
      if (debug) {
	aplog("ARP didn't match a target\n");
      }
      continue;
    }
    if (debug) {
      aplog("ARP matched a router and a target\n");
    }
  }

exit:

  {
    time_t now = time(NULL);
    aplog("Exiting at time %ld\n", now);
  }
  
  FreeRecvState(&recv_state);
  if (send_sock >= 0) {
    close(send_sock);
  }
  if (nl >= 0) {
    close(nl);
  }
  if (timer >= 0) {
    close(timer);
  }
  return 0;
}

// Updates the template send buffer with the current receive state.
void UpdateSendBuffer(char *send_frame, RecvState *state) {
  uint16_t *send_proto = (uint16_t *)&(send_frame[MAC_LEN+MAC_LEN]);
  ArpHeader *send_arp = (ArpHeader *)&(send_frame[ETH_HLEN]);

  memset(send_frame, 0, ETH_MAXPACKET);

  // Ethernet header
  // send_frame[0] will be populated later
  if (RecvStateIsValid(state)) {
    memcpy(&(send_frame[MAC_LEN]), &(state->local_mac), sizeof state->local_mac);
  } else {
    memset(&(send_frame[MAC_LEN]), 0, sizeof state->local_mac);
  }
  *send_proto = htons(ETH_P_ARP);
  // ARP header
  send_arp->header_type = htons(ARPHRD_ETHER);
  send_arp->proto_type = htons(ETH_P_IP);
  send_arp->header_len = MAC_LEN;
  send_arp->proto_len = IP_LEN;
  send_arp->op_code = htons(ARPOP_REPLY);
  if (RecvStateIsValid(state)) {
    memcpy(&(send_arp->sender_mac), &(state->local_mac), sizeof state->local_mac);
    memcpy(&(send_arp->sender_ip), &(state->local_ip.sin_addr), sizeof send_arp->sender_ip);
  } else {
    memset(&(send_arp->sender_mac), 0, sizeof state->local_mac);
    memset(&(send_arp->sender_ip), 0, sizeof send_arp->sender_ip);
  }
  // target_mac and target_ip will be populated later.
  if (debug) {
    aplog("Sender template: type 0x%x proto 0x%x hlen %u plen %u op %u, "
	  "smac %02x:%02x:%02x:%02x:%02x:%02x sip %u.%u.%u.%u "
	  "tmac %02x:%02x:%02x:%02x:%02x:%02x tip %u.%u.%u.%u\n",
	  ntohs(send_arp->header_type), ntohs(send_arp->proto_type),
	  send_arp->header_len, send_arp->proto_len,
	  ntohs(send_arp->op_code),
	  send_arp->sender_mac[0], send_arp->sender_mac[1], send_arp->sender_mac[2],
	  send_arp->sender_mac[3], send_arp->sender_mac[4], send_arp->sender_mac[5],
	  send_arp->sender_ip[0], send_arp->sender_ip[1],
	  send_arp->sender_ip[2], send_arp->sender_ip[3],
	  send_arp->target_mac[0], send_arp->target_mac[1], send_arp->target_mac[2],
	  send_arp->target_mac[3], send_arp->target_mac[4], send_arp->target_mac[5],
	  send_arp->target_ip[0], send_arp->target_ip[1],
	  send_arp->target_ip[2], send_arp->target_ip[3]);
  }
}

void aplog(const char *restrict format, ...) {
  va_list va;
  va_start(va, format);
  vdprintf(logfd, format, va);
  va_end(va);
  if (debug) {
    fsync(logfd);
  }
}
