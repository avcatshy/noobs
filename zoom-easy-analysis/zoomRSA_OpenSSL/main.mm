//
//  zoomRSA_OpenSSL
//
//  Created by phone on 2021/6/11.
//
#include <stdio.h>
#include <strings.h>

#import <openssl/aes.h>
#import <openssl/rsa.h>
#import <openssl/evp.h>
#import <openssl/asn1t.h>
#import <openssl/x509.h>
#import <openssl/pem.h>

char* Public=(char*)"-----BEGIN PUBLIC KEY-----\n" \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhHloLsfrcUyAtpF21GG342clr\n" \
"IopKVva8gkpw0Gr1B76QQGghLfb0/MvHg35OmxavjgXhBWa38rrH+pQ5gn1hF9QAp8vNI\n" \
"pHn5U4EshXk/CffyDV5EckQIcaxa/qxVNnqyPNUoPkaBL4tWYcgkzSFtfE7fqFnOJYuoA\n" \
"dDr3sTGGvIgY7vY7iO19mCG96WOo065L79XlGTGuOrp4y/EYdSnH+L+4u0wg15GW7nnoD\n" \
"TK9puIpF4l/KzcHXhThz1nXBRfiR1gnlxdlMs6OaYmqoKlxqas9bMWCfRnVyzFD9aymxn\n" \
"Lf8S4t7ITHWuu1mljxSm9EMPtUn0Fd157HSrvy4fQIDAQAB\n" \
"-----END PUBLIC KEY-----\n";


void my_rsa_encrypt_func(EVP_PKEY* evpkey,const unsigned char* data){
    int iret=0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpkey, 0);
    EVP_PKEY_CTX *p = ctx;
    unsigned char* outbuf=NULL;
    size_t outLen=0;
    if(ctx){
        if(EVP_PKEY_encrypt_init(ctx)<1){
            iret=8;
        }else if (RSA_pkey_ctx_ctrl(p, 0xFFFFFFFF, 4097, 4, 0) < 1){
            iret=9;
        }else{
            if ( (signed int)EVP_PKEY_encrypt(p, 0, &outLen, data, strlen((char*)data)) < 1 )
            {
                iret = 10;
            }else{
                outbuf=(unsigned char*)malloc(outLen);
                memset(outbuf,0, outLen);
                if(EVP_PKEY_encrypt(ctx, outbuf,&outLen, data, strlen((char*)data))<1){
                    iret=11;
                }else{
                    iret=0;
                    for(int x=0;x<outLen;x++){
                        printf("%02x", outbuf[x]);
                    }
                }
            }
        }
    }
    if (outbuf){
        free(outbuf);
        outbuf=NULL;
    }
}


// COPIED from stackoverflow
int char2int(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  printf("Invalid input string");
  exit(0);
  return 0;
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large

// COPIED from stackoverflow
void hex2bin(const char* src, char* target)
{
  while(*src && src[1])
  {
    // if(char2int(*src)!=0 && char2int(src[1])!=0){
        *(target++) = char2int(*src)*16 + char2int(src[1]);
        src += 2;
  }
}

int main(int argc, char* argv[]){
    if (argc <2){
        return 0;
    }
    
    unsigned char* data=(unsigned char*)malloc(2*strlen((char*)argv[1]));
    hex2bin(argv[1], (char*)data);

    if (strlen((char* )data) !=32){
        printf("argv[1] len is: %lu\n", strlen((char* )data));
        return 0;
    }

    BIO* bio=BIO_new_mem_buf(Public, (int)strlen(Public));
    EVP_PKEY* v29=PEM_read_bio_PUBKEY(bio, 0, 0, 0);
    size_t len = i2d_PUBKEY(v29, NULL);
    unsigned char* public_key = NULL;

    int iret=i2d_PUBKEY(v29, &public_key);
    EVP_PKEY* evpkey=d2i_PUBKEY(0,(const unsigned char**) &public_key, iret);
    if (evpkey){
        my_rsa_encrypt_func(evpkey, data);
    }
    
    return 0;
}

