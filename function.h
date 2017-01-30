#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if.h>
#include <malloc.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <math.h>
#include <pthread.h>

#ifndef _function_H_
#define _function_H_

#define SEQ_LEN 4
#define PORT_LEN 4
#define KEY_IV_LEN 16
#define MAX_MEM_PACKET 10000
#define MAX_SEQUENCE_NUMBER 0xfffffff
#define HMAC_SIZE 50
#define BUFFER_SIZE 2000
#define MAX_TEXT_SIZE 1000000
#define SSL_SERVER_PORT 8888
#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)
int randomNumber(int min,int max);
int hashpassword(char* ovalue, char* hvalue);
int encrypt_aes_128_cbc(char* input,char* output,int length,unsigned char* key,unsigned char* iv);
int decrypt_aes_128_cbc(char* input,char *output,int length,unsigned char* key,unsigned char* iv);
int hashMac_sha256(char* input, char* hmac, int length, unsigned char* hkey);
int ShowCerts(SSL *ssl);
unsigned char* genratekey(int key_len);
int checkconnect(int socket);
unsigned char* genseq(int seq,int len);
int getseq(unsigned char* seq,int len);
int checkreply(int mempacket[],int length,int seq);
int updatemempack(int mempacket[],int length,int count,int nseq);
void usage();

void ssltunnel(void * myssl);
void udptunnel();
void showMenu();

#endif
