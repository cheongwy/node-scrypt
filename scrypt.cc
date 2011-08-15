#include <v8.h>
#include <node.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// link as C since we compile as C and not C++
// see wscript
extern "C" {
	#include <crypto_scrypt.h>
}

using namespace node;
using namespace v8;

#define ENCBLOCK 65536

static int getsalt(uint8_t salt[32]);

class Scrypt: ObjectWrap
{
	private:
	int m_count;

	public:
	
	Scrypt(): m_count(0){}
	~Scrypt() {}
	
	static Persistent<FunctionTemplate> s_ct;
	static void Initialize(Handle<Object> target)
	{
		HandleScope scope;
		
		Local<FunctionTemplate> t = FunctionTemplate::New(New);
		
		s_ct = Persistent<FunctionTemplate>::New(t);
		s_ct->InstanceTemplate()->SetInternalFieldCount(1);
		s_ct->SetClassName(String::NewSymbol("Scrypt"));
		
		NODE_SET_PROTOTYPE_METHOD(s_ct, "encrypt", Encrypt);
		
		target->Set(String::NewSymbol("Scrypt"), s_ct->GetFunction());
	}
	
    static Handle<Value> New(const Arguments &args) {
        HandleScope scope;
		
        Scrypt *scrypt = new Scrypt();
        scrypt->Wrap(args.This());
        return args.This();
    }
	
	static Handle<Value> Encrypt(const Arguments& args)
	{
		HandleScope scope;
		Scrypt* scrypt = ObjectWrap::Unwrap<Scrypt>(args.This());
		scrypt->m_count++;
		Local<String> result = String::New("Hello Scrypt");
		return scope.Close(result);
	}

};

static Handle<Value> Encrypt(const Arguments& args)
{
	HandleScope scope;
	const char *usage = "usage: encrypt(passwd)";
	if (args.Length() != 1) {
		return ThrowException(Exception::Error(String::New(usage)));
	}
	
	Local<String> password = args[0]->ToString();
	char passwd_val;
	char * passwd = &passwd_val;
	password->WriteUtf8(passwd);
	printf ("Incoming password: [%s]\n",passwd);
	
	int len = 64;
	uint8_t dk[len];
	uint8_t * key_enc = dk;
	size_t buflen = len;
	
	int N = 16384;
	int r = 8;
	int p = 1;
	//uint8_t salt[32]; 
	char salt[32] = "695d5df642041b86f2775d2b4f0f722";
	
	const char *salt_err_msg = "Unable to obtain salt";	
	int rc;
	//if ((rc = getsalt(salt)) != 0)
	//	return ThrowException(Exception::Error(String::New(salt_err_msg)));
	//printf ("Salt: [%s]\n", salt);
	
	const char *enc_err_msg = "An error occured when encrypting password";	
	if( rc = crypto_scrypt((uint8_t *)passwd, strlen(passwd), (uint8_t *)salt, 32, N, r, p, dk, buflen)!=0)
		return ThrowException(Exception::Error(String::New(enc_err_msg)));
	
	//int ret = scryptenc_buf(inbuf, inbuflen, outbuf, passwd, passwdlen, maxmem, maxmem_frac, maxtime);
	printf ("[%u] is the encrypted password\n",dk);
	
	Local<String> result = String::New((char *)key_enc, len);
	return scope.Close(result);
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

Persistent<FunctionTemplate> Scrypt::s_ct;

extern "C" void init(Handle<Object> target)
{
	//Scrypt::Initialize(target);
	HandleScope scope;
	//target->Set(String::NewSymbol("Scrypt"), String::New("Hello Scrypt"));
	NODE_SET_METHOD(target, "encrypt", Encrypt);
}