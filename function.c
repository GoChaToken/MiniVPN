#include "function.h"
int randomNumber(int min,int max){

	int dev_random_fd = -1;
	char *next_random_byte;
	int bytes_to_read;
	unsigned random_value;
	

	if(min > max){
		return 0;
	}
	
	if(dev_random_fd == -1)
	{
		dev_random_fd = open("/dev/urandom",O_RDONLY);
		if(dev_random_fd == -1){
			return 0;
		}
	}
	
	next_random_byte = (char *)&random_value;
	bytes_to_read = sizeof(random_value);
	
	do{
		int bytes_read;
		bytes_read = read(dev_random_fd,next_random_byte,bytes_to_read);
		bytes_to_read -= bytes_read;
		next_random_byte += bytes_read;
	}while(bytes_to_read > 0);
	close(dev_random_fd);
	return min+(random_value % (max-min+1));
}

int hashpassword(char* ovalue, char* hvalue){
	EVP_MD_CTX mdctx;
	const EVP_MD *md;
	int length;
	EVP_MD_CTX_init(&mdctx);
	md = EVP_md5();
	EVP_DigestInit_ex(&mdctx,md,NULL);
	EVP_DigestUpdate(&mdctx,ovalue,strlen(ovalue));
	EVP_DigestFinal_ex(&mdctx,hvalue,&length);
	EVP_MD_CTX_cleanup(&mdctx);
	return length;	
}

int encrypt_aes_128_cbc(char* input,char* output,int length,unsigned char* key,unsigned char* iv){
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	int aes_len,aes_out_len;
	cipher = EVP_aes_128_cbc();

	EVP_CIPHER_CTX_init(&ctx);
	if((EVP_EncryptInit_ex(&ctx,cipher,NULL, key,iv)) != 1){
		PERROR("EVP_EncryptInit_ex()");
	}
	aes_len = 0;
	EVP_EncryptUpdate(&ctx,output,&aes_out_len,input,length);
	aes_len += aes_out_len;
	EVP_EncryptFinal_ex(&ctx,output+aes_len,&aes_out_len);
	aes_len += aes_out_len;
	EVP_CIPHER_CTX_cleanup(&ctx);
	return aes_len;
	
}

int decrypt_aes_128_cbc(char* input,char* output,int length,unsigned char* key,unsigned char* iv){
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	int aes_len,aes_out_len;
	cipher = EVP_aes_128_cbc();
	
	EVP_CIPHER_CTX_init(&ctx);
	if((EVP_DecryptInit_ex(&ctx,cipher,NULL, key,iv)) != 1){
		PERROR("EVP_DecryptInit_ex()");
	}
	aes_len = 0;
	EVP_DecryptUpdate(&ctx,output,&aes_out_len,input,length);
	aes_len+=aes_out_len;
	EVP_DecryptFinal_ex(&ctx,output+aes_len,&aes_out_len);
	aes_len+=aes_out_len;
	EVP_CIPHER_CTX_cleanup(&ctx);
	return aes_len;
	
}

int hashMac_sha256(char* input, char* hmac, int length, unsigned char* hkey){
	int hmac_length;
	HMAC_CTX hctx;
	const EVP_MD* md = EVP_sha256();
	
	HMAC_CTX_init(&hctx);
	HMAC_Init_ex(&hctx,hkey,16,md,NULL);
	HMAC_Update(&hctx,input,length);
	HMAC_Final(&hctx,hmac,&hmac_length);
	HMAC_CTX_cleanup(&hctx);
	return hmac_length;
	
}

int ShowCerts(SSL *ssl){

	int re;
	X509 * cert;
	char * line;
	
	char * searchcn;

	cert = SSL_get_peer_certificate(ssl);
	X509_NAME *subject = X509_get_subject_name(cert);
	int nid_cn = OBJ_txt2nid("CN");
	char common_name[256];
	X509_NAME_get_text_by_NID(subject,nid_cn,common_name,256);
	printf("comman name: %s \n",common_name);
	searchcn = strstr(common_name,"taokanServer");
	if(searchcn != NULL){
		//printf("there\n");
		if(searchcn[strlen("taokanServer")] == '/'){
			re = 1;

		}else if(searchcn[strlen("taokanServer")] == '\0'){
			re = 1;
		}else{
			re = 0;
		}
	}else{
		//printf("hello\n");
		re = 0;
	}
	if(cert != NULL){
		printf("the information of certification:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert),0,0);
		printf("who: %s\n",line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
		printf("who ca: %s\n",line);
		free(line);
		X509_free(cert);
	
	}else{
		printf("no CA\n");
	}
	return re;
		
}

unsigned char* genratekey(int key_len){
	unsigned char* key;
	int i;
	int k;
	key = (unsigned char*)malloc(key_len);
	for(i = 0; i < key_len; i++){
		k = randomNumber(0,10000)%256;
		//printf("gen :%d\n",k);
		key[i] = k;
	}
	return key;

}

int checkconnect(int socket){
	int re;
	int optval,optlen;
	optlen = sizeof(optval);

	if(socket < 0)
		re = 0;
	
	getsockopt(socket,SOL_SOCKET,SO_ERROR,(char*)&optval,&optlen);
	if(optval == 0){
		re = 1;
	}else{
		re = 0;
	}
	return re;
	
}

void showMenu(){
	printf("welcome to use miniVPN!\n");
	printf("you can use the commands below,please input the number\n");
	printf("1.change the key and iv\n");
	printf("2.quit\n");
}

int updatemempack(int mempacket[],int length,int count,int nseq){
	if(count == length){
		count = 0;
	}
	mempacket[count] = nseq;
	count ++;
	return count;
}

int checkreply(int mempacket[],int length,int seq){
	int i;
	int re = 1;
	for(i = 0; i < length;i++){
		if(mempacket[i] == seq){
			re = 0;
			break;
		}
	}
	return re;
}

int getseq(unsigned char* seq,int len){
	int re = 0;
	int i;
	for(i = len-1; i >= 0; i--){
		re += seq[i] * pow(256,len-1-i);
	}
	return re;
}

unsigned char* genseq(int seq,int len){
	unsigned char* seqnum;
	int i;
	int temp = seq;
	seqnum = (unsigned char*)malloc(len);
	for(i = 1; i < len + 1; i++){
		temp = seq%(int)pow(16.0,2.0);
		seqnum[len-i] = temp;
		seq = seq/(int)pow(16.0,2.0);
	}
	return seqnum;
}

void usage()
{
	fprintf(stderr, "Usage: minivpnserver [-c ip]\n");
	exit(0);
}
