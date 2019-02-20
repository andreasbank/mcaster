/**
 * mcaster.c - A simple test program for sending (x)or receiving multicast
 * Copyright(C) 2013-2019 Andreas Bank, andreas.mikael.bank@gmail.com
 *
 * This code is public domain.
 */
#define VERSION "1.0"

/* Needed for struct ip_mreq */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#ifdef __WIN__
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#endif

#ifndef STRX
#define STRX(X) #X
#define STR(X) STRX(X)
#endif

#define TRUE 1
#define FALSE 0
#define SPAM_PORT 6000
#define SPAM_GROUP_ADDRESS "239.0.0.1"
#define RECV_BUFFER 100

/* Function declarations */
static void usage(void);
static char *sdup(const char *str);
const char *find_argument_value(const char *arg, int argc, const char **argv,
		char **err);
static int find_interface(struct in_addr *interface, const char *address,
		char **err);
static int parse_arguments(int argc, const char **argv, int *server_mode,
		struct in_addr *mcast_address, unsigned int *mcast_port,
		struct in_addr *mcast_interface, char const **spam_string, char **err);
static int join_multicast_group(int sock, struct in_addr *mcast_address,
		struct in_addr *mcast_interface, char **err);
static int run_receiver(int sock, struct in_addr *mcast_address,
		unsigned int mcast_port, struct in_addr *mcast_interface,
		struct sockaddr_in *addr, char **err);
static int start_sender(int sock, struct in_addr *mcast_address,
		unsigned int mcast_port, struct in_addr *mcast_interface,
		struct sockaddr_in *addr, const char *spam_string, char **err);
void exit_sig(int signr);

/* Global variables */
static volatile int want_exit = FALSE;
static char *time_string;
static const char *prog_name;

/**
 * Show program usage.
 */
static void usage(void) {
	printf("\nmcast.c - Multicast test program %s\nCopyright(C) 2013 by "
			"Andreas Bank, <andreas.mikael.bank@gmail.com>\n\n", VERSION);
	printf("Usage:\n\t%s [-s][-ap][-S]\n\n", prog_name);
	printf("\t-s: start in server mode (as opposed to client mode), -S is "
			"ignored\n");
	printf("\t-a: server mode: address to listen on; client mode: mcast group "
			"address\n");
	printf("\t-p: server mode: port to listen o; client mode: mcast group "
			"port\n");
	printf("\t-S: string to be sent, default is \"time is DDD MMM DD HH:mm:ss "
			"YYYY\"\n\n");
}

/**
 * Duplicate a string.
 *
 * @param str The string to duplicate.
 *
 * @return A new copy of the string. This must be freed with free() when no
 *         longer used.
 */
static char *sdup(const char *str) {
	if (!str)
		return NULL;

	size_t len = strlen(str);
	char *dup = malloc(len + 1);
	memset(dup, '\0', len);

	return strncpy(dup, str, len);
}

/**
 * Handle exit signals.
 */
void exit_sig(int signr) {
	printf("\nCaught exit signal (%d). To force-quit press ctrl+c again\n\n",
			signr);
	if (want_exit)
		exit(0);
	want_exit = TRUE;
}

/**
 * Fins specified argument value.
 *
 * @param arg The argument to look for.
 * @param argc The number of arguments in the argument list.
 * @param argv The argument list.
 * @param err A pointer that will point to an error description if an error
 *        occurs. Must be freed with free() when no longer used.
 *
 * @return The value of the argument, if found, NULL otherwise. If NULL is
 *         returned and an error has occurred, err will contain the description
 *         of the error. If err is NULL no error has occurred.
 */
const char *find_argument_value(const char *arg, int argc, const char **argv,
		char **err) {
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(arg, argv[i]) == 0) {
			switch (argv[i][1]) {
			case 's':
				/* server mode */
				return "1";
				break;
			case 'a':
				/* Multicast address */
				if (i == argc - 1 || (i < argc - 1 && argv[i+1][0] == '-')) {
					*err = sdup("No address given after '-a'");
					return NULL;
				}
				return argv[i+1];
			case 'p':
				/* Multicast port */
				if (i == argc - 1 || (i < argc - 1 && argv[i+1][0] == '-')) {
					*err = sdup("No port given after '-p'");
					return NULL;
				}
				return argv[i+1];
			case 'i':
				/* Ethernet interface to use when sending */
				if (i == argc-1 || (i < argc - 1 && argv[i+1][0] == '-')) {
					*err = sdup("No interface given after '-i'");
					return NULL;
				}
				return argv[i+1];
			case 'S':
				/* String to send as multicast data */
				if (i == argc-1 || (i < argc - 1 && argv[i+1][0] == '-')) {
					*err = sdup("No string given after '-S'");
					return NULL;
				}
				return argv[i+1];
			}
		}
	}
	return NULL;
}

/**
 * Try to find a matching interface for the given interface name or IP address.
 *
 * @param interface A pointer to the interface structure to fill.
 * @param address The name or address to match with an interface.
 */
int find_interface(struct in_addr *interface, const char *address, char **err) {
	/* TODO: for porting to Windows see:
	   http://msdn.microsoft.com/en-us/library/aa365915.aspx */
	struct ifaddrs *interfaces, *ifa;
	char *paddr;
	int found = FALSE;
	if(getifaddrs(&interfaces)<0) {
		*err = sdup("getifaddr");
		return FALSE;
	}
	for (ifa = interfaces; ifa && ifa->ifa_next; ifa = ifa->ifa_next) {
		paddr = inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);

		if ((strcmp(address, ifa->ifa_name) == 0) || (strcmp(address, paddr) == 0)) {
			if (ifa->ifa_addr->sa_family == AF_INET) {
				if (strcmp(address, ifa->ifa_name) == 0) {
					printf("Matched ifa_name: %s (paddr: %s)\n", ifa->ifa_name, paddr);
				}
				else if (strcmp(address, paddr) == 0) {
					printf("Matched paddr: %s (ifa_name: %s)\n", paddr, ifa->ifa_name);
				}
				found = TRUE;
				interface->s_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
				break;
			}
		}
	}
	if (interfaces) {
		freeifaddrs(interfaces);
	}
	return found;
}
/**
 * Parse the input arguments.
 *
 * @param argc The number of input arguments.
 * @param argv The input arguments.
 * @param mcast_address A pointer to a in_addr to store the multicast
 *        address.
 * @param mcast_port A pointer to an integer to set to the multicast port.
 * @param mcast_interface A pointer to a in_addr to set the multicast interface
 *        in.
 * @param spam_string The string to send as mutlicast data. Needs to be freed
 *        with free() when no longer used.
 * @param err A pointer that will point to an error description if an error
 *        occurs. Must be freed with free() when no longer used.
 */
static int parse_arguments(int argc, const char **argv, int *server_mode,
		struct in_addr *mcast_address, unsigned int *mcast_port,
		struct in_addr *mcast_interface, char const **spam_string, char **err) {
	const char *arg_value;

	/* Server mode argument */
	arg_value = find_argument_value("-s", argc, argv, err);
	if(arg_value && strcmp(arg_value, "1") == 0)
		*server_mode = TRUE;
	printf("server_mode=%d\n", *server_mode);

	/* Multicast group address argument */
	if ((arg_value = find_argument_value("-a", argc, argv, err))) {
		if (inet_pton(AF_INET, arg_value, mcast_address) <= 0)
			*err = sdup("Invalid mcast address");
	} else {
		mcast_address->s_addr = inet_addr(SPAM_GROUP_ADDRESS);
	}
	printf("mcast_address=%s\n", arg_value ? arg_value : SPAM_GROUP_ADDRESS);

	/* Multicast port argument */
	if ((arg_value = find_argument_value("-p", argc, argv, err))) {
		// TODO: replace atoi()
		*mcast_port = htons(atoi(arg_value));
	}
	printf("mcast_port=%s\n", arg_value ? arg_value : STRX(SPAM_PORT));

	/* Interface/IP address argument */
	if ((arg_value = find_argument_value("-i", argc, argv, err))) {
		if (!find_interface(mcast_interface, arg_value, err)) {
			if (!*err)
				*err = sdup("Could not find any matching interface");
			return 1;
		}
	}
	printf("mcast_interface=%s\n",
			arg_value ? arg_value : "INADDR_ANY (default)");

	/* Spam string argument (only applicable in server mode) */
	if (!*server_mode) {
		if ((arg_value = find_argument_value("-S", argc, argv, err)))
			*spam_string = arg_value;
		if (*err)
			return 1;
		printf("spam_string=%s\n", *spam_string ? *spam_string :
				"\"time is DDD MMM DD HH:mm:ss YYYY (default)\"");
	}

	return 0;
}

static int join_multicast_group(int sock, struct in_addr *mcast_address,
		struct in_addr *mcast_interface, char **err) {
	struct ip_mreq mreq;

	mreq.imr_multiaddr.s_addr = mcast_address->s_addr;
	mreq.imr_interface.s_addr = mcast_interface->s_addr;
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
			sizeof(mreq)) < 0) {
		*err = sdup("setsockopt mreq");
		return 1;
	}

	return 0;
}

static int run_receiver(int sock, struct in_addr *mcast_address,
		unsigned int mcast_port, struct in_addr *mcast_interface,
		struct sockaddr_in *addr, char **err) {
	char message[RECV_BUFFER];
	int reuse = 1;

	/* Create and bind to UDP socket */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse,
			sizeof(reuse)) == -1) {
		*err = sdup("SO_REUSEADDR");
		return 1;
	}
	/* linux >= 3.9
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse,
			sizeof(reuse)) == -1) {
		*err = sdup("SO_REUSEPORT");
		return 1;
	}
	*/
	if (bind(sock, addr, sizeof(*addr)) < 0) {
		*err = sdup("bind");
		return 1;
	}

	/* Set a route out to the chosen interface */
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, mcast_interface,
			sizeof(*mcast_interface))) {
		*err = sdup("setsockopt() IF_MULTICAST_IF");
		return 1;
	}

	/* Join the multicast group */
	if (join_multicast_group(sock, mcast_address, mcast_interface, err)) {
		return 1;
	}

	/* Start receiving data */
	while (!want_exit) {
		socklen_t slen = sizeof(*addr);
		int success = recvfrom(sock, message, RECV_BUFFER - 1, 0, addr, &slen);
		if (success < 0) {
			*err = sdup("recvfrom");
			return 1;
		}
		message[success] = '\0';
		time_string = malloc(50);
		time_t t = time(NULL);
		strftime(time_string, 10, "%I:%M%p", localtime(&t));
		// TODO: fix leak inet_ntoa()
		printf("[%s][%s][%dB] \"%s\"\n", time_string, inet_ntoa(addr->sin_addr),
				success, message);
	}

	return 0;
}

static int start_sender(int sock, struct in_addr *mcast_address,
		unsigned int mcast_port, struct in_addr *mcast_interface,
		struct sockaddr_in *addr, const char *spam_string, char **err) {
	char message[RECV_BUFFER];

	/* Set a route out to the chosen interface */
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, mcast_interface,
			sizeof(*mcast_interface))) {
		*err = sdup("setsockopt() IF_MULTICAST_IF");
		return 1;
	}

	/* Join the multicast group */
	if (join_multicast_group(sock, mcast_address, mcast_interface, err))
		return 1;

	unsigned int count = 0;
	while (!want_exit) {
		if (spam_string) {
			strncpy(message, spam_string, sizeof(message) - 1);
		} else {
			time_t t = time(NULL);
			sprintf(message, "time is %-24.24s", ctime(&t));
		}
		printf("\rsending(\e[31;1m%d\e[m): \e[1;37;40m\"%s\"\e[m     ", ++count,
				message);
		fflush(stdout);
		int success = sendto(sock, message, strlen(message), 0,
				(struct sockaddr *)addr, sizeof(*addr));
		if(success < 0) {
			*err = sdup("sendto");
			return 1;
		}
		sleep(1);
	}

	return 0;
}

int main(int argc, char **argv) {
	static int sock;
	struct sockaddr_in addr;
	char *err = NULL;
	int server_mode = FALSE;
	struct in_addr mcast_address;
	unsigned int mcast_port = htons(SPAM_PORT);
	const char *spam_string = NULL;
	struct in_addr mcast_interface;

	mcast_address.s_addr = inet_addr(SPAM_GROUP_ADDRESS);
	mcast_interface.s_addr = htonl(INADDR_ANY);
	prog_name = argv[0];

	/* Set up signal handler */
	signal(SIGTERM, &exit_sig);
	signal(SIGABRT, &exit_sig);
	signal(SIGINT, &exit_sig);

	/* Pars arguments */
	if (parse_arguments(argc, (const char **)argv, &server_mode, &mcast_address,
			&mcast_port, &mcast_interface, &spam_string, &err)) {
		printf("err");
		goto err;
	}

	/* Create UDP socket */
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		err = sdup("socket");
		goto err;
	}

	/* Create the destination address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = mcast_address;
	addr.sin_port = mcast_port;

	printf("Starting in %s mode...\n\n", server_mode ? "server" : "client");
	if (server_mode) {
		/* server mode */
		run_receiver(sock, &mcast_address, mcast_port, &mcast_interface, &addr,
				&err);
	} else {
		/* client mode */
		start_sender(sock, &mcast_address, mcast_port, &mcast_interface, &addr,
				spam_string, &err);
	}

err:
	if (sock) {
		close(sock);
		sock = 0;
	}
	if (time_string) {
		free(time_string);
	}
	if (err) {
		printf("Error: %s\n", err);
		usage();

		return 1;
	}

	return 0;
}
