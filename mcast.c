/* 

mcast.c - A simple program for sending (x)or receiveing multicast
Copyright(C) 2013 by Andreas Bank, andreas.mikael.bank@gmail.com

Updated: 2013-06-21 20:23

*/
#define VERSION "0.9A"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>

#define TRUE 1
#define FALSE 0
#define SPAM_PORT 6000
#define SPAM_GROUP_ADDRESS "239.0.0.1"
#define RECV_BUFFER 100

void eraseTermChars();
void cleanup();
void exitSig();
char *findArgumentValue(const char *arg, int argc, char **argv);
void findInterface(struct in_addr *interface, const char *address);

int sock;
char *message;
char *time_string;

int main(int argc, char **argv) {
	struct sockaddr_in addr;
	int success;
	unsigned int count = 0;
	size_t addr_size;
	struct ip_mreq mreq;
	message = malloc(sizeof(char)*RECV_BUFFER);
	int server_mode = FALSE;
	int af_family = AF_INET;
	struct in_addr mcast_address;
	unsigned short mcast_port = htons(SPAM_PORT);
	char *spam_string;
	struct in_addr mcast_interface;
	mcast_address.s_addr = htonl(INADDR_ANY);
	mcast_interface.s_addr = htonl(INADDR_ANY);

	/* sort out arguments */
	{
		char *tmpStr = findArgumentValue("-s", argc, argv);
		if(tmpStr && strcmp(tmpStr, "1") == 0) {
			server_mode = TRUE;
		}
		printf("server_mode=%d\n", server_mode);
		tmpStr = findArgumentValue("-a", argc, argv);
		if(tmpStr && (inet_pton(AF_INET, tmpStr, &mcast_address) <= 0)) {
			errno = EINVAL;
			cleanup("Invalid mcast address: ");
		}
		if(!tmpStr) {
			printf("mcast_address=%s (default)\n", SPAM_GROUP_ADDRESS);
		}
		else {
			printf("mcast_address=%s\n", tmpStr);
		}
		tmpStr = findArgumentValue("-p", argc, argv);
		if(tmpStr) {
			mcast_port = htons(atoi(tmpStr));
			printf("mcast_port=%s\n", tmpStr);
		}
		else {
			printf("mcast_port=%d (default)\n", SPAM_PORT);
		}
		/*tmpStr = findArgumentValue("-i", argc, argv);
		if(tmpStr) {
			mcast_interface = findInterface(&mcast_interface, tmpStr);
			printf("mcast_interface=%s\n", tmpStr);
		}
		else {
			printf("mcast_port=%d (default)\n", SPAM_PORT);
		}*/
		if(!server_mode) {
			spam_string = findArgumentValue("-S", argc, argv);
			if(spam_string) {
				printf("spam_string=%s\n", spam_string);
			}
			else {
				printf("spam_string=\"time is DDD MMM DD HH:mm:ss YYYY (default)\"\n");
			}
		}
	}

	/* init socket */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		cleanup("socket");
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = af_family;
	addr.sin_addr = mcast_address;
	addr.sin_port = mcast_port;
	addr_size = sizeof(addr);

	/* signal management */
	signal(SIGTERM, &exitSig);
	signal(SIGABRT, &exitSig);
	signal(SIGINT, &exitSig);

	printf("\nmcast.c - QA Multicast tool version %s\nCopyright(C) 2013 by Andreas Bank, <andreas.mikael.bank@gmail.com>\n\n", VERSION);
	printf("Usage:\n\t%s [-s][-ap][-S]\n\n", argv[0]);
	printf("\t-s: start in server mode (as opposed to client mode), -S is ignored\n");
	printf("\t-a: server mode: address to listen on; client mode: mcast group address\n");
	printf("\t-p: server mode: port to listen o; client mode: mcast group port\n");
	printf("\t-S: string to be sent, default is \"time is DDD MMM DD HH:mm:ss YYYY\"\n\n");

	if(server_mode) {
		/* server mode */
		printf("Starting in server mode...\n\n");
		int reuse = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
			cleanup("SO_REUSEADDR");
		}
		/* linux >= 3.9
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) == -1) {
			cleanup("SO_REUSEPORT");
		}
		*/
		if(bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {	  
			cleanup("bind");
		}
		if(mcast_address.s_addr) {
			mreq.imr_multiaddr.s_addr = mcast_address.s_addr;
		}
		else {
			mreq.imr_multiaddr.s_addr = inet_addr(SPAM_GROUP_ADDRESS);
		}
		mreq.imr_interface.s_addr = mcast_interface.s_addr;
		if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
			cleanup("setsockopt mreq");
		}
		while(TRUE) {
			memset(message, 0, RECV_BUFFER);
			success = recvfrom(sock, message, RECV_BUFFER, 0, (struct sockaddr *) &addr, (socklen_t *)&addr_size);
			if(success < 0) {
				cleanup("recvfrom: ");
			}
			time_t t = time(NULL);
			time_string = malloc(sizeof(char)*50);
			strftime(time_string, 10, "%I:%M%p", localtime(&t));
			printf("[%s][%s][%dB] \"%s\"\n", time_string, inet_ntoa(addr.sin_addr), success, message);
		}
	}
	else {
		/* client mode */
		printf("Starting in client mode...\n\n");
		while(TRUE) {
			if(spam_string) {
				strcpy(message, spam_string);
			}
			else {
				time_t t = time(NULL);
				sprintf(message, "time is %-24.24s", ctime(&t));
			}
			printf("\rsending(\e[31;1m%d\e[m): \e[1;37;40m\"%s\"\e[m     ", ++count, message);
			fflush(stdout);
			success = sendto(sock, message, strlen(message), 0, (struct sockaddr *) &addr, addr_size);
			if(success < 0) {
 				cleanup("sendto");
			}
			sleep(1);
		}
	}
	cleanup(NULL);
	return 0;
}

void eraseTermChars(int count) {
	int i;
	for(i=0; i<count; i++) {
		printf("\b");
	}
}

void cleanup(const char *error) {
	if(sock) {
		close(sock);
		sock = 0;
	}
	if(message) {
		free(message);
		message = NULL;
	}
	if(time_string) {
		free(time_string);
		time_string = NULL;
	}
	if(error) {
		perror(error);
		exit(1);
	}
}

void exitSig() {
	cleanup(NULL);
	printf("\nCaught exit signal.\n\n");
	exit(0);
}

char *findArgumentValue(const char *arg, int argc, char **argv) {
	int i;
	char *tmpStr = malloc(sizeof(char)*50);
	for(i=1; i<argc; i++) {
		if(strcmp(arg, argv[i]) == 0) {
			switch(argv[i][1]) {
			case 's':
				/* server mode */
				return "1";
				break;
			case 'a':
				/* multicast address */
				if(i==argc-1 || (i<argc-1 && argv[i+1][0] == '-')) {
					sprintf(tmpStr, "No address given after '-a'");
					errno = EINVAL;
					cleanup(tmpStr);
				}
				return argv[i+1];
			case 'p':
				/* multicast port */
				if(i==argc-1 || (i<argc-1 && argv[i+1][0] == '-')) {
					sprintf(tmpStr, "No port given after '-p'");
					errno = EINVAL;
					cleanup(tmpStr);
				}
				return argv[i+1];
			case 'S':
				/* string to be spammed with */
				if(i==argc-1 || (i<argc-1 && argv[i+1][0] == '-')) {
					sprintf(tmpStr, "No string given after '-S'");
					errno = EINVAL;
					cleanup(tmpStr);
				}
				return argv[i+1];
			}
		}
	}
	return NULL;
}

void findInterface(struct in_addr *interface, const char *address) {
	struct addrinfo *res, hints;
	// TODO: find matching interface
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;
	/*
	if(getaddrinfo(NULL, address, &hints, &res) != 0) {
		cleanup("getaddrinfo");
	}
	interface->s_addr = inet_addr(inet_ntoa(*((struct in_addr*)res->h_addr_list[0])));
	freeaddrinfo(res);
	*/
}

