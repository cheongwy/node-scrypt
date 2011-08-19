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
static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);

static Handle<Value> Encrypt(const Arguments& args)
{
	HandleScope scope;
	const char *usage = "usage: encrypt(passwd)";
	if (args.Length() != 1) {
		return ThrowException(Exception::Error(String::New(usage)));
	}
	
	Local<String> password = args[0]->ToString();

	String::Utf8Value passwd(password);
	//printf ("Incoming password: [%s]\n",*passwd);
	
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
	
	std::string encrypted = base64_encode(dk, len);
	//char * encrypted = base64(dk, len);
	//printf ("[%s] is the encrypted password\n",encrypted);
	std::cout << "encoded: " << encrypted << std::endl;
	
	Local<String> result = String::New(encrypted.c_str());
	return scope.Close(result);
}

static const std::string base64_chars = 
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";


static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];
	
	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;
			
			for(i = 0; (i <4) ; i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}
	
	if (i)
	{
		for(j = i; j < 3; j++)
			char_array_3[j] = '\0';
		
		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;
		
		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];
		
		while((i++ < 3))
			ret += '=';
		
	}
	
	return ret;
	
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