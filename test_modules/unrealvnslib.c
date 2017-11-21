/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *   UMDEV: Virtual Device in Userspace
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <vumodule.h>
#include <errno.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>

#include <string.h>

VU_PROTOTYPES(unrealvnslib)

struct vu_module_t vu_module = {
	.name = "unrealvnslib",
	.description = "unrealvnslib: tcp-ip layer for stack unification"
};

struct ip_mask{
	int i_prefix;
	char *c_prefix;
};

/* questa forse è megli definirla nell'header della libreria */
const struct ip_mask mask_len[] = {
	{32, "255.255.255.255"},
	{24, "255.255.255.0"},
	{16, "255.255.0.0"},
	{8, "255.0.0.0"}
};

int fd;
int vu_unrealvnslib_msocket(const char *path, int domain, int type, int protocol) {
	if (path != NULL) {
		errno = EINVAL;
		return -1;
	}
	if(domain==AF_NETLINK){
		fd=socket(domain, type, protocol);
		printk("socket:%d\n", fd);
	}
	else{
		return socket(domain, type, protocol);
	}
	return fd;
}

static struct vuht_entry_t *ht[3];
static int afs[3] = {AF_INET, AF_INET6, AF_NETLINK};

struct nlmsghdr* hd;

ssize_t vu_unrealvnslib_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){

		struct nlmsghdr* header = hd = (struct nlmsghdr*) buf;
		if(fd == sockfd){
			//unsigned char* ip_string[sizeof(struct in6_addr)];
			char str[INET6_ADDRSTRLEN];
			if(header->nlmsg_type == RTM_NEWROUTE || header->nlmsg_type == RTM_DELROUTE || header->nlmsg_type == RTM_GETROUTE){
				struct rtmsg* rtm = (struct rtmsg*)(NLMSG_DATA(header));
				struct rtattr* attr = (struct rtattr*)((void*)(((char*)rtm)+ sizeof(struct rtmsg)));

				if(rtm->rtm_family == AF_INET6){
					struct in6_addr* ip6_a = (struct in6_addr*)RTA_DATA(attr);
					inet_ntop(rtm->rtm_family, ip6_a, str, INET6_ADDRSTRLEN);
					printk("IPv6 address route: %s\n",str);
				}
				else if(rtm->rtm_family == AF_INET){
					struct in_addr* ip4_a = (struct in_addr*)RTA_DATA(attr);
					printk("IPv4 address route: %s\n", inet_ntoa(*ip4_a));
				}

			}
			else if(header->nlmsg_type == RTM_NEWADDR || header->nlmsg_type == RTM_DELADDR || header->nlmsg_type == RTM_GETADDR){
				struct ifaddrmsg* ifa = (struct ifaddrmsg*)(NLMSG_DATA(header));
				struct rtattr* attr = (struct rtattr*)((void*)(((char*)ifa)+ sizeof(struct ifaddrmsg)));
				//struct in_addr* ip_a = (struct in_addr*)RTA_DATA(attr);
				if(ifa->ifa_family == AF_INET6){
					struct in6_addr* ip6_a = (struct in6_addr*)RTA_DATA(attr);
					inet_ntop(ifa->ifa_family, ip6_a, str, INET6_ADDRSTRLEN);
					printk("IPv6 address add: %s\n",str);
					inet_pton(ifa->ifa_family, str, ip6_a);
				}
				else if(ifa->ifa_family == AF_INET){
					struct in_addr* ip4_a = (struct in_addr*)RTA_DATA(attr);
					printk("IPv4 address add: %s\n", inet_ntoa(*ip4_a));
				}
				//printk("prefix: %d\n", ifa->ifa_prefixlen);
				//printk("ip_add: %s\n", inet_ntoa(*ip_a));
			}
			else if(header->nlmsg_type == RTM_NEWLINK || header->nlmsg_type == RTM_DELLINK || header->nlmsg_type == RTM_GETLINK){
				//struct ifinfomsg* ifi = (struct ifinfomsg*)(NLMSG_DATA(header));
				//struct rtattr* attr = (struct rtattr*)((void*)(((char*)ifi)+ sizeof(struct ifinfomsg)));
			}
			printk("sendto:%d\n", sockfd);
			return sendto(sockfd, buf, len, flags,dest_addr, addrlen);
	}
	return sendto(sockfd, buf, len, flags,dest_addr, addrlen);
}

ssize_t vu_unrealvnslib_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t *addrlen){
		printk("recv:%d\n", sockfd);
		if(fd == sockfd){
			//#if 0
			struct my_recv_msg{
				struct nlmsghdr* msg_hdr;
				struct nlmsgerr* payload;
			};

			struct my_recv_msg* fake_msg = malloc(sizeof(struct my_recv_msg));
			fake_msg->msg_hdr = malloc(sizeof(struct nlmsghdr));

			//struct nlmsghdr* send_msg_hdr = malloc(sizeof(struct nlmsghdr));
			//memcpy(hd, send_msg_hdr, sizeof(struct nlmsghdr));
			fake_msg->payload->error = 0;
			fake_msg->payload->msg = *hd;
			fake_msg->msg_hdr->nlmsg_type = NLMSG_ERROR;

			fake_msg->msg_hdr->nlmsg_len = 36;

			fake_msg->msg_hdr->nlmsg_flags = NLM_F_CAPPED;

			fake_msg->msg_hdr->nlmsg_seq = hd->nlmsg_seq;
			fake_msg->msg_hdr->nlmsg_pid = 29375;

			buf = (void*)fake_msg;
		  /*{len=36, type=NLMSG_ERROR, flags=NLM_F_CAPPED, seq=1511196611, pid=29375},
		  {error=0, msg={len=40, type=RTM_NEWADDR, flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, seq=1511196611, pid=0}}},
		  iov_len=32768}*/

			printk("sizeof buf: %d\n", sizeof(*((struct nlmsghdr*)buf)));
			printk("recv:%d\n", sockfd);

			return (36);
			//return recvfrom(sockfd, buf, len, flags,dest_addr, addrlen);
			//#endif
			/*int s = recvfrom(sockfd, buf, len, flags,dest_addr, addrlen);
			struct nlmsghdr* head = (struct nlmsghdr*)buf;
			struct nlmsgerr* err = (struct nlmsgerr*)(NLMSG_DATA(head));
			int* iovlen = (int*)(NLMSG_DATA(err));
			printk("recv len: %d\n",head->nlmsg_len);
			printk("error: %d\n",err->error);
			printk("iovlen: %d\n",*iovlen);
			return s;*/
		}
	  return recvfrom(sockfd, buf, len, flags,dest_addr, addrlen);
}

void *vu_unrealvnslib_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
	int i;

	vu_syscall_handler(s, bind) = bind;
	vu_syscall_handler(s, connect) = connect;
	vu_syscall_handler(s, listen) = listen;
	vu_syscall_handler(s, accept4) = accept4;
	vu_syscall_handler(s, getsockname) = getsockname;
	vu_syscall_handler(s, getpeername) = getpeername;
	//vu_syscall_handler(s, sendto) = sendto;
	//vu_syscall_handler(s, recvfrom) = recvfrom;
	vu_syscall_handler(s, shutdown) = shutdown;
	vu_syscall_handler(s, setsockopt) = setsockopt;
	vu_syscall_handler(s, getsockopt) = getsockopt;
	vu_syscall_handler(s, epoll_ctl) = epoll_ctl;
	vu_syscall_handler(s, close) = close;

	for (i = 0; i < 3; i++)
		ht[i] = vuht_add(CHECKSOCKET, &afs[i], sizeof(int), s, NULL, NULL, 0);
	return NULL;
}

int vu_unrealvnslib_fini(void *private) {
	int i;
	for (i = 0; i < 3; i++) {
		if (ht[i] && vuht_del(ht[i], 0) == 0)
			ht[i] = NULL;
	}
	return 0;
}
