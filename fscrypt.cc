// Implementing CBC using BF_set_Key and BF_ecb_encrypt
// Amogh Lale
// alale1@binghamton.edu


#include<stdio.h>
#include"openssl/blowfish.h"
#include<stdlib.h>
#include<string.h>
#define SIZE 16

BF_KEY key;

unsigned char *out = (unsigned char *)calloc(100, sizeof(char));
unsigned char *out2 = (unsigned char *)calloc(100, sizeof(char));
char initial_vector[]="00000000";

void *fs_encrypt(void *plaintext, int bufsize, char *keystr,int *resultlen)
{
	unsigned char P[bufsize];
	int i,j,k;
        unsigned char *internalcipher = out;
	unsigned char * plaintext_main=(unsigned char *) plaintext; 

 	//set up BF_KEY key
        BF_set_key(&key, SIZE, (const unsigned char *)keystr);
	    
        // XOR 1 block of plaintext with intial vector   
        for(i=0;i<8;i++)
	{
		P[i]=(* plaintext_main)^initial_vector[i];  
		plaintext_main++;
	
	}
    
        // XOR other blocks of input plaintext 
	i = 0;	
	bufsize = bufsize - 8;
	BF_ecb_encrypt(&P[i], out, &key, BF_ENCRYPT);
	j = 8;

	while(bufsize > 0)
	{
		for(k=0;k<8;k++)
		{
			P[j++]= (*out) ^ (* plaintext_main); 
			out++;
			plaintext_main++; 
     		}
		i=i+8;  	
		BF_ecb_encrypt(&P[i], out, &key, BF_ENCRYPT);
	  	bufsize = bufsize - 8;
	}
	
        // return internal cipher text generated to main.cc 
	*resultlen=strlen((const char *)internalcipher);
	return (void *) internalcipher;

}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr,int *resultlen)
{
	int i,j,k;
        unsigned char P[bufsize+1];
	unsigned char *p=P;
        unsigned char * ciphertext_main=(unsigned char *) ciphertext;
	unsigned char * cipher=(unsigned char *) ciphertext;
	unsigned char *finalplain = out2;    
 
       //Decrypt ciphertext   	          
        BF_ecb_encrypt(ciphertext_main, out2, &key, BF_DECRYPT);

       // XOR output  obtained from decryption with the initialization vector 
        for(k=0;k<8;k++)
        {
          P[k]= (*out2)^initial_vector[k]; 
	  out2++;        
	}
	
        // Decrypt other blocks to obtain plaintext
         j=0;
         i=8; 
	 bufsize = bufsize - 8;
         while(bufsize>0)
		{              
			ciphertext_main = ciphertext_main + 8;
			BF_ecb_encrypt(ciphertext_main, out2, &key, BF_DECRYPT);
                   	for(k=0;k<8;k++,i++,j++)
                      	{
                          P[i]=(*cipher) ^ (*out2);
			  out2++;
			  cipher++;
                        }  
			bufsize = bufsize - 8;
	        }

       // return decryption result 
 	*resultlen=strlen((const char*) P);
	return (void *) p;
}

