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
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "arpproxy.h"
#include "parsenl.h"
#include "recvstate.h"

void SendRouteQuery(const RecvState *state, int nl) {
  struct {
    struct nlmsghdr header;
    struct rtmsg message;
  } request = {0};

  request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.message));
  request.header.nlmsg_type = RTM_GETROUTE;
  // NLM_F_DUMP seems to be needed to get default route.
  request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.header.nlmsg_seq = time(NULL);
  request.message.rtm_family = AF_INET;
  request.message.rtm_table = RT_TABLE_MAIN;
  request.message.rtm_scope = RT_SCOPE_UNIVERSE;
  request.message.rtm_type = RTN_UNICAST;
  if (send(nl, &request, request.header.nlmsg_len, 0) < 0) {
    dprintf(logfd, "Failed to send route request: %d\n", errno);
  }
  if (debug) {
    dprintf(logfd, "Sent route request\n");
  }
}

int CheckCanIgnore(const RecvState *state, struct nlmsghdr *msg, ssize_t len) {
  int can_ignore = 1;

  // Loop through all the messages
  for (struct nlmsghdr * nh = msg; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
    if (nh->nlmsg_type == NLMSG_DONE) {
      if (debug) {
	dprintf(logfd, "Got a done message\n");
      }
      break;
    }
    if (nh->nlmsg_type == NLMSG_ERROR) {
      dprintf(logfd, "Got an error message\n");
      can_ignore = 0;
      break;
    }
    if (debug) {
      dprintf(logfd, "Got netlink msg type %u len %u flags 0x%x seq %u pid %u\n",
	      nh->nlmsg_type, nh->nlmsg_len, nh->nlmsg_flags, nh->nlmsg_seq, nh->nlmsg_pid);
    }
    switch (nh->nlmsg_type) {
    case RTM_DELADDR:
    case RTM_NEWADDR: {
      struct ifaddrmsg *addr_msg = NLMSG_DATA(nh);
      const char *msg_type_string = nh->nlmsg_type == RTM_NEWADDR ? "new" : "del";
      if (debug || nh->nlmsg_type == RTM_DELADDR) {
	printf("Got netlink %s addr fam %u prefixlen %u flags %u scope %u link index %u\n",
	       msg_type_string,
	       addr_msg->ifa_family, addr_msg->ifa_prefixlen, addr_msg->ifa_flags,
	       addr_msg->ifa_scope, addr_msg->ifa_index);
      }
      // don't care about addr_msg->ifa_prefixlen
      // don't care about addr_msg->ifa_flag
      // don't care about addr_msg->ifa_scope
      if (addr_msg->ifa_family != AF_INET) {
	dprintf(logfd, "Got unexpected family %u\n", addr_msg->ifa_family);
	can_ignore = 0;
	continue;
      }
      // For now we'll not ignore any delete message
      if (nh->nlmsg_type == RTM_DELADDR) {
	if (debug) {
	  dprintf(logfd, "Not ignoring delete message\n");
	}
        can_ignore = 0;
	continue;
      } else { // RTM_NEWADDR
	if (!RecvStateIsValid(state)) {
	  time_t now = time(NULL);
	  dprintf(logfd, "Don't currently have an adapter, "
		  "so not ignoring message (time is %ld)\n", now);
	  can_ignore = 0;
          continue;
	} else if (addr_msg->ifa_index != state->device_sockaddr.sll_ifindex) {
	  if (debug) {
	    dprintf(logfd, "Index doesn't match %u vs %u\n",
		    addr_msg->ifa_index, state->device_sockaddr.sll_ifindex);
	  }
	  can_ignore = 0;
	  continue;
	}
      }
      int all_attr_len = nh->nlmsg_len - NLMSG_LENGTH(sizeof *addr_msg);
      void *local_addr = NULL;
      char *interface_name = NULL;
      int for_this_interface = 0;
      for (struct rtattr *attr = IFLA_RTA(addr_msg); RTA_OK(attr, all_attr_len);
	   attr = RTA_NEXT(attr, all_attr_len)) {
	int attr_len = RTA_PAYLOAD(attr);
	if (debug) {
	  dprintf(logfd, "Got netlink %saddr attr type %u len %u\n",
		  msg_type_string, attr->rta_type, attr_len);
	}
	switch(attr->rta_type) {
	case IFA_LOCAL:
	  if (attr_len != sizeof state->local_ip.sin_addr) {
	    dprintf(logfd, "Local IP not expected length: %d\n", attr_len);
	    can_ignore = 0;
	  } else {
	    local_addr = RTA_DATA(attr);
	    if (debug) {
	      dprintf(logfd, "Interface IP 0x%08x\n", *(int *)local_addr);
	    }
	  }
	  break;
	case IFA_LABEL:
	  interface_name = RTA_DATA(attr);
	  if (debug) {
	    dprintf(logfd, "Interface name %s\n", interface_name);
	  }
	  break;
	case IFA_BROADCAST:
	  // Don't care about this.
	  if (debug) {
	    dprintf(logfd, "Ignoring broadcast attribute\n");
	  }
	  break;
	case IFA_FLAGS:
	  // Don't care about this.
	  if (debug) {
            dprintf(logfd, "Ignoring flags attribute\n");
          }
	  break;
	case IFA_CACHEINFO:
	  // Don't care about this.
	  if (debug) {
            dprintf(logfd, "Ignoring cache attribute\n");
          }
	  break;
	default:
	  // Likely don't care about IFA_UNSPEC, IFA_ADDRESS,
	  // IFA_ANYCAST, IFA_MULTICAST, IFA_RT_PRIORITY,
	  // IFA_TARGET_NETNSID, or IFA_PROTO but won't ignore
	  // them until they've actually been seen.
	  dprintf(logfd, "Got unexpected attr type %u len %u\n",
		  attr->rta_type, attr_len);
	  can_ignore = 0;
	}
      }
      if (debug && local_addr && interface_name) {
	dprintf(logfd, "Notification for interface %s with IP 0x%08x\n",
		interface_name, *(int *)local_addr);
      }
      if (interface_name) {
	int recogize_interface = 0;
	for (int i = 0; i < state->num_other_interfaces; ++i) {
	  if (strcmp(state->other_interfaces[i], interface_name) == 0) {
	    recogize_interface = 1;
	  }
	  if (strcmp(state->net_interface, interface_name) == 0) {
	    for_this_interface = 1;
	  }
	}
	if (!recogize_interface) {
	  dprintf(logfd, "Interface not recognized: %s\n", interface_name);
	  can_ignore = 0;
	} else if (debug) {
	  dprintf(logfd, "Recognized interface: %s\n", interface_name);
	}
      }
      // We only care about addr change if it's for this interface.
      if (local_addr && for_this_interface) {
        if (memcmp(&(state->local_ip.sin_addr), local_addr,
		   sizeof state->local_ip.sin_addr)) {
	  dprintf(logfd, "Interface IP changed from 0x%08x to 0x%08x\n",
		  *(int *)&(state->local_ip.sin_addr), *(int *)local_addr);
	  can_ignore = 0;
	} else if (debug) {
	  dprintf(logfd, "Interface IP matched expectation: 0x%08x\n",
		  *(int *)&(state->local_ip.sin_addr));
	}
      }
      break;
    }
    // We only expect to get RTM_NEWROUTE because we requested an update
    // after a NIC change.
    case RTM_NEWROUTE: {
      struct rtmsg *msg = NLMSG_DATA(nh);
      if (debug) {
        printf("Got netlink route fam %u destlen %u srclen %u tos %u "
	       "table %u proto %u scope %u type %u flags %u\n",
               msg->rtm_family, msg->rtm_dst_len, msg->rtm_src_len,
	       msg->rtm_tos, msg->rtm_table, msg->rtm_protocol,
	       msg->rtm_scope, msg->rtm_type, msg->rtm_flags);
      }
      if (msg->rtm_family != AF_INET) {
        dprintf(logfd, "Got unexpected route family %u\n", msg->rtm_family);
        continue;
      }
      int all_attr_len = nh->nlmsg_len - NLMSG_LENGTH(sizeof *msg);
      int have_gateway = 0;
      int gateway = 0;
      int have_oif = 0;
      int oif = 0;
      for (struct rtattr *attr = RTM_RTA(msg); RTA_OK(attr, all_attr_len);
           attr = RTA_NEXT(attr, all_attr_len)) {
        int attr_len = RTA_PAYLOAD(attr);
        if (debug) {
          dprintf(logfd, "Got netlink route attr type %u len %u\n",
                  attr->rta_type, attr_len);
        }
        switch(attr->rta_type) {
        case RTA_DST: {
	  int *dest = RTA_DATA(attr);
	  if (attr_len != sizeof *dest) {
	    dprintf(logfd, "Unexpected size %d for RTA_DST", attr_len);
	  } else if (debug) {
	    dprintf(logfd, "Route dest IP 0x%08x\n", *dest);
	  }
	  break;
	}
	case RTA_GATEWAY: {
          int *gateway_ptr = RTA_DATA(attr);
          if (attr_len != sizeof gateway) {
            dprintf(logfd, "Unexpected size %d for RTA_GATEWAY", attr_len);
          } else {
	    have_gateway = 1;
	    gateway = *gateway_ptr;
	    if (debug) {
	      dprintf(logfd, "Route gateway 0x%08x\n", gateway);
	    }
	  }
          break;
        }
	case RTA_OIF: {
          int *oif_ptr = RTA_DATA(attr);
	  if (attr_len != sizeof oif) {
	    dprintf(logfd, "Unexpected size %d for RTA_OIF", attr_len);
	  } else {
	    have_oif = 1;
	    oif = *oif_ptr;
	    if (debug) {
	      dprintf(logfd, "Route oif 0x%08x\n", oif);
	    }
	  }
          break;
        }
	case RTA_PRIORITY: {
          int *priority = RTA_DATA(attr);
          if (attr_len != sizeof *priority) {
            dprintf(logfd, "Unexpected size %d for RTA_PRIORITY", attr_len);
          } else if (debug) {
            dprintf(logfd, "Route priority 0x%08x\n", *priority);
          }
          break;
        }
        case RTA_TABLE: {
          int *table = RTA_DATA(attr);
          if (attr_len != sizeof *table) {
            dprintf(logfd, "Unexpected size %d for RTA_TABLE", attr_len);
          } else if (debug) {
            dprintf(logfd, "Route table 0x%08x\n", *table);
          }
          break;
        }
	case RTA_UID: {
          int *uid = RTA_DATA(attr);
          if (attr_len != sizeof *uid) {
            dprintf(logfd, "Unexpected size %d for RTA_UID", attr_len);
          } else if (debug) {
            dprintf(logfd, "Route uid 0x%08x\n", *uid);
          }
          break;
        }
	case RTA_PREFSRC:
	  if (debug) {
	    dprintf(logfd, "Ignoring RTA_PREFSRC\n");
	  }
	  break;
	case RTA_CACHEINFO:
	  if (debug) {
	    dprintf(logfd, "Ignoring RTA_CACHEINFO\n");
	  }
	  break;
	default:
	  dprintf(logfd, "Got unrecognized route attr type %u len %u\n",
		  attr->rta_type, attr_len);
	  break;
	}
      }
      if (have_gateway && have_oif) {
	// We requested RT_TABLE_MAIN(254), RT_SCOPE_UNIVERSE(0), and RTN_UNICAST
	// so assuming there's no need to explicit check/verify this in the response.
	// Checking rtm_tos is TBD.
	// rtm_protocol can be RTPROT_DHCP for DHCP but can vary so won't check

	// If this is the default route and for the NIC interface we're using.
	if (msg->rtm_dst_len == 0 && msg->rtm_src_len == 0 &&
	    oif == state->device_sockaddr.sll_ifindex) {
	  if (gateway != *(int*)&state->router) {
	    time_t now = time(NULL);
	    dprintf(logfd, "Updated router from %u.%u.%u.%u",
		    state->router[0], state->router[1], state->router[2], state->router[3]);
	    *(int*)&state->router = gateway;
	    dprintf(logfd, " to %u.%u.%u.%u at %ld\n",
                    state->router[0], state->router[1], state->router[2], state->router[3], now);
	  } else if (debug) {
	    dprintf(logfd, "Router is still accurate: %08x\n", gateway);
	  }
	} else if (debug) {
	  dprintf(logfd, "Ignoring router update\n");
	}
      }
      break;
    }
    default:
      // Other options might include RTM_GETADDR.
      dprintf(logfd, "Got unexpected msg type %u\n", nh->nlmsg_type);
      can_ignore = 0;
    }
  }

  if (debug) {
    dprintf(logfd, "Result of ignore: %d\n", can_ignore);
  }
  return can_ignore;
}
