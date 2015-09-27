// BF_cbc_encrypt
// Amogh Lale
// alale1@binghamton.edu

#include<stdio.h>
#include"openssl/blowfish.h"
#include<stdlib.h>
#include<string.h>
#define SIZE 16

BF_KEY key;

// *out and *out2 are returned from *fs_encrypt and *fs_decrypt respectively 
unsigned char *out = (unsigned char *)calloc(100, sizeof(char));
unsigned char *out2 = (unsigned char *)calloc(100, sizeof(char));

void *fs_encrypt(void *plaintext, int bufsize, char *keystr,int *resultlen)
{
	
	unsigned char initial_vector[9]="00000000";
	unsigned char * plaintext_main=(unsigned char *) plaintext; 
 	BF_set_key(&key, SIZE, (const unsigned char *)keystr);
	unsigned char *internalcipher = out; 
        
        // Encrypt using BF_cbc_encrypt 
        BF_cbc_encrypt(plaintext_main, out,bufsize, &key, initial_vector, BF_ENCRYPT);
	
        //send encrypted result to main.cc
        *resultlen=strlen((const char *)out);
	return (void *) out;

}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr,int *resultlen)
{
	unsigned char * ciphertext_main=(unsigned char *) ciphertext;
	unsigned char *finalplain = out2;    
 	unsigned char initial_vector[9]="00000000";
        
        //Decrypt using BF_cbc_encrypt           
        BF_cbc_encrypt(ciphertext_main, out2,bufsize, &key, initial_vector, BF_DECRYPT);      

        // send decrypted result to main.cc
        *resultlen=strlen((const char*) out2);
	return (void *) out2;
}

