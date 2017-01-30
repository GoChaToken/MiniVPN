/*
Author: Kan Tao
*/
#include "function.h"

//hard code key and iv
/*unsigned char hkey[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
unsigned char key[16] = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
unsigned char iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};*/


char magic_word[50];
unsigned char hkey[KEY_IV_LEN];
unsigned char key[KEY_IV_LEN];
unsigned char iv[KEY_IV_LEN];
struct sockaddr_in udp_server;
char command[50];
int fd;
fd_set fdset;


int main(int argc, char *argv[])
{
	int ssl_socket;
	int i;
	int TUNMODE = IFF_TUN;
	int ssl_port = SSL_SERVER_PORT;
	int MODE = 0;
	char *ip,c;
	struct ifreq ifr;
	int port;
	SSL *ssl;
	SSL_CTX * ssl_ctx;
	pthread_t ssl_tun,udp_tun;
	struct sockaddr_in vpnserver;
	int ssl_verify;
	int ssl_len;
	char buf[2000];

	unsigned char username_input[50];
	unsigned char password_input[50];


	while ((c = getopt(argc, argv, "c:h")) != -1) {
		printf("%c\n",c);
		switch(c){
			case 'h':
				usage();
			case 'c':
				MODE = 2;
				ip = optarg;
				break;
			default:
				usage();
		}
	}
	if(MODE == 0) usage();

	if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = TUNMODE;
	strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");

	printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ssl_ctx =SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_load_verify_locations(ssl_ctx,"ca.crt",NULL);

	if((ssl_socket = socket(AF_INET,SOCK_STREAM,0)) == -1)
		PERROR("ssl_socket fail");

	vpnserver.sin_family = AF_INET;
	vpnserver.sin_port = htons(ssl_port);
	inet_aton(ip, &vpnserver.sin_addr);

	if(connect(ssl_socket, (struct sockaddr *)&vpnserver, sizeof(vpnserver)) !=0)
		PERROR("CONNECT");

	ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ssl,ssl_socket);

	if(SSL_connect(ssl) == -1){
		PERROR("ssl_connect");
	}else{
		if(ShowCerts(ssl) == 0){
				PERROR("SHOW CERTS");
			}
			ssl_verify = SSL_get_verify_result(ssl);
			if(ssl_verify == X509_V_OK){
				printf("authority\n");
			}else{
				printf("invalid ca\n");
				SSL_shutdown(ssl);
				SSL_free(ssl);
				close(ssl_socket);
				SSL_CTX_free(ssl_ctx);
			}
			ssl_len = SSL_read(ssl,buf,BUFFER_SIZE);
			printf("receive %s\n",buf);
			bzero(buf,BUFFER_SIZE);
			strcpy(buf,"client->server");
			ssl_len = SSL_write(ssl,buf,strlen(buf));
			bzero(buf,BUFFER_SIZE);
			printf("please input the username:\n");
			gets(username_input);
			printf("please input the password:\n");
			gets(password_input);
			bzero(buf,BUFFER_SIZE);
			memcpy(buf,username_input,strlen(username_input));
			ssl_len = SSL_write(ssl,buf,strlen(buf));
			bzero(buf,BUFFER_SIZE);
			memcpy(buf,password_input,strlen(password_input));
			printf("password len %d\n",strlen(password_input));
			ssl_len = SSL_write(ssl,buf,strlen(buf));
			bzero(buf,BUFFER_SIZE);
			
	
			ssl_len = SSL_read(ssl,buf,BUFFER_SIZE);
			memcpy(key,buf,KEY_IV_LEN);
			memcpy(iv,buf+KEY_IV_LEN,KEY_IV_LEN);
			memcpy(hkey,buf+KEY_IV_LEN+KEY_IV_LEN,KEY_IV_LEN);
			bzero(buf,BUFFER_SIZE);
			printf("key: \n");
			for(i = 0; i < 16; i++){
				printf("%02x ",key[i]);
			}
			printf("\n");
			ssl_len = SSL_read(ssl,magic_word,50);
			bzero(buf,BUFFER_SIZE);
			ssl_len = SSL_read(ssl,buf,BUFFER_SIZE);
			port = getseq(buf,PORT_LEN);
			printf("port: %d\n",port);

			if(pthread_create(&ssl_tun,NULL,(void*)ssltunnel,(void*)ssl) == -1){
				PERROR("pthread_create");
			}

			udp_server.sin_family = AF_INET;
			udp_server.sin_port = htons(port);
			inet_aton(ip, &udp_server.sin_addr);
			if(pthread_create(&udp_tun,NULL,(void*)udptunnel,NULL) == -1){
				PERROR("pthread create");
			}
		
			
			
	}

	

	/*port = 8000;
	udp_server.sin_family = AF_INET;
	udp_server.sin_port = htons(port);
	inet_aton(ip, &udp_server.sin_addr);
	if(pthread_create(&pudp_tun,NULL,(void*)udptunnel,NULL) == -1){
		PERROR("pthread create");
	}*/
	/*while(1){
	}*/
	pthread_join(ssl_tun,NULL);
	return 0;
}

void ssltunnel(void * myssl){
	SSL *ssl;
	ssl = (SSL *)myssl;
	int ssl_len;
	char buf[BUFFER_SIZE];
	while(1){
		showMenu();
		gets(command);
		//bzero(buf,2000);
		command[strlen(command)] = '\0';
		if(strlen(command) > 1){
			printf("invalid command!!\n");
		}else{
			switch(command[0]){
				case '1':
				printf("change\n");
				ssl_len = SSL_write(ssl,command,strlen(command));

				ssl_len = SSL_read(ssl,buf,BUFFER_SIZE);
				memcpy(key,buf,KEY_IV_LEN);
				memcpy(iv,buf+KEY_IV_LEN,KEY_IV_LEN);
				memcpy(hkey,buf+KEY_IV_LEN+KEY_IV_LEN,KEY_IV_LEN);
				break;
				case '2':
				printf("quit\n");
				ssl_len = SSL_write(ssl,command,strlen(command));
				exit(0);
				break;
				default:
				printf("invalid command!!\n");
				break;
				}
		}
	}
	
}

void udptunnel(){
	int s_udp,l,i;
	int aesl,hmacl;
	int soutlen;
	char buf[BUFFER_SIZE];
	char aesbuf[BUFFER_SIZE];
	char hmac[HMAC_SIZE];
	int fromlen = sizeof(udp_server);
	struct sockaddr_in sout;

	int sseq;
	int rseq;
	unsigned char sseqnum[SEQ_LEN];
	unsigned char rseqnum[SEQ_LEN];
	int mempacket[MAX_MEM_PACKET];
	int memednum;

	s_udp = socket(PF_INET, SOCK_DGRAM,0);
	l =sendto(s_udp, magic_word, strlen(magic_word), 0, (struct sockaddr *)&udp_server, sizeof(udp_server));
	if (l < 0) PERROR("sendto");
	l = recvfrom(s_udp,buf, sizeof(buf), 0, (struct sockaddr *)&udp_server, &fromlen);
	if (l < 0) PERROR("recvfrom");
	if (strncmp(magic_word, buf, strlen(magic_word) != 0))
		ERROR("Bad magic word for peer\n");
	printf("Connection with %s:%i established\n", 
	      inet_ntoa(udp_server.sin_addr), ntohs(udp_server.sin_port));

	bzero(mempacket,MAX_MEM_PACKET);
	sseq = 1;
	rseq = 1;
	memednum = 0;

	while(1){
		printf("key: \n");
		for(i = 0; i < 16; i++){
			printf("%02x ",key[i]);
		}
		printf("\n");
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s_udp, &fdset);
		if (select(fd+s_udp+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
		if (FD_ISSET(fd, &fdset)) {
			l = read(fd, buf, sizeof(buf));
			if (l < 0) PERROR("read");
			sprintf(iv,"%s",genratekey(KEY_IV_LEN));
			memcpy(sseqnum,genseq(sseq,SEQ_LEN),SEQ_LEN);
			aesl = encrypt_aes_128_cbc(buf,aesbuf,l,key,iv);
			//hmacl = hashMac_sha256(aesbuf,hmac,aesl,hkey);

			bzero(buf,BUFFER_SIZE);
			memcpy(buf,sseqnum,SEQ_LEN);
			memcpy(buf+SEQ_LEN,iv,KEY_IV_LEN);
			memcpy(buf+KEY_IV_LEN+SEQ_LEN,aesbuf,aesl);
			hmacl = hashMac_sha256(buf,hmac,aesl+KEY_IV_LEN+SEQ_LEN,hkey);
			memcpy(buf+KEY_IV_LEN+aesl+SEQ_LEN,hmac,hmacl);
			//memcpy(aesbuf+aesl,hmac,hmacl);
			//if (sendto(s_udp, aesbuf, aesl+hmacl, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
			if (sendto(s_udp, buf, aesl+hmacl+KEY_IV_LEN+SEQ_LEN, 0, (struct sockaddr *)&udp_server, fromlen) < 0) PERROR("sendto");
			sseq++;
			if(sseq == MAX_SEQUENCE_NUMBER){
				sseq = 1;
			}
		}else{
			l = recvfrom(s_udp, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
			if ((sout.sin_addr.s_addr != udp_server.sin_addr.s_addr) || (sout.sin_port != udp_server.sin_port)){
				printf("Got packet from  %s:%i instead of %s:%i\n", 
				       inet_ntoa(sout.sin_addr), ntohs(sout.sin_port),
				       inet_ntoa(udp_server.sin_addr), ntohs(udp_server.sin_port));
			}else{
				memcpy(rseqnum,buf,SEQ_LEN);
				rseq = getseq(rseqnum,SEQ_LEN);
				if(checkreply(mempacket,MAX_MEM_PACKET,rseq) == 1){
				memednum = updatemempack(mempacket,MAX_MEM_PACKET,memednum,rseq);
				memcpy(iv,buf+SEQ_LEN,KEY_IV_LEN);
				aesl = decrypt_aes_128_cbc(buf+KEY_IV_LEN+SEQ_LEN,aesbuf,l-32-KEY_IV_LEN-SEQ_LEN,key,iv);
				hmacl = hashMac_sha256(buf,hmac,l-32,hkey);
				if(memcmp(buf+l-32,hmac,32) == 0){
				if (write(fd, aesbuf, aesl) < 0) PERROR("write");
				}
				}else{
					printf("replay attack!!\n");
				}
			}
		}
		
		
	}
}
