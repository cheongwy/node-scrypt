#include <v8.h>
#include <node.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// link as C since we compile as C and not C++
// see wscript
extern "C" {
	#include <crypto_scrypt.h>
}

#include <iostream>
using namespace std;

using namespace node;
using namespace v8;

#define ENCBLOCK 65536

static int getsalt(uint8_t salt[32]);
static char *base64(const unsigned char *input, int length);
static char *unbase64(unsigned char *input, int length);

static Handle<Value> Encrypt(const Arguments& args)
{
	HandleScope scope;
	const char *usage = "usage: encrypt(passwd)";
	if (args.Length() != 1) {
		return ThrowException(Exception::Error(String::New(usage)));
	}
	
	Local<String> password = args[0]->ToString();

	String::Utf8Value passwd(password);
	printf ("Incoming password: [%s]\n",*passwd);
	
	int len = 32;
	uint8_t dk[len];
	size_t buflen = len;
	
	int N = 1024;
	int r = 8;
	int p = 8;
	String::Utf8Value salt(String::New(""));
	
	const char *salt_err_msg = "Unable to obtain salt";	
	int rc;
//	if ((rc = getsalt(salt)) != 0)
//		return ThrowException(Exception::Error(String::New(salt_err_msg)));
//	printf ("Salt: [%s]\n", base64(salt,32));

	const char *enc_err_msg = "An error occured when encrypting password";	
	if( rc = crypto_scrypt((uint8_t *)*passwd, strlen(*passwd), (uint8_t *)*salt, strlen(*salt), N, r, p, dk, buflen)!=0)
		return ThrowException(Exception::Error(String::New(enc_err_msg)));
	
	//int ret = scryptenc_buf(inbuf, inbuflen, outbuf, passwd, passwdlen, maxmem, maxmem_frac, maxtime);
	char *encrypted = base64(dk, len);
	printf ("[%s] is the encrypted password\n",encrypted);
	
	Local<String> result = String::New(encrypted);
	return scope.Close(result);
}

static char *base64(const unsigned char *input, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;
	
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);
	
	char *buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length] = 0;
	
	BIO_free_all(b64);
	
	return buff;
}

/* Not used but just in case we need it for salting */
static char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;
	
	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);
	
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf(input, length);
	BIO_push(b64, bmem);
	
	BIO_read(bmem, buffer, length);
	
	BIO_free_all(bmem);
	
	return buffer;
}


/* Not used. Unless we want to store the random salts along with the password */
static int getsalt(uint8_t salt[32])
{
	int fd;
	ssize_t lenread;
	uint8_t * buf = salt;
	size_t buflen = 32;
	
	/* Open /dev/urandom. */
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		goto err0;
	
	/* Read bytes until we have filled the buffer. */
	while (buflen > 0) {
		if ((lenread = read(fd, buf, buflen)) == -1)
			goto err1;
		
		/* The random device should never EOF. */
		if (lenread == 0)
			goto err1;
		
		/* We're partly done. */
		buf += lenread;
		buflen -= lenread;
	}
	
	/* Close the device. */
	while (close(fd) == -1) {
		if (errno != EINTR)
			goto err0;
	}
	
	/* Success! */
	return (0);
	
err1:
	close(fd);
err0:
	/* Failure! */
	return (4);
}


extern "C" void init(Handle<Object> target)
{
	//Scrypt::Initialize(target);
	HandleScope scope;
	//target->Set(String::NewSymbol("Scrypt"), String::New("Hello Scrypt"));
	NODE_SET_METHOD(target, "encrypt", Encrypt);
}