#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}

int hex_to_int(char c)
{
    if (c >= 97)
        c = c - 32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9) result--;
    return result;
}

int hex_to_ascii(const char c, const char d)
{
	int high = hex_to_int(c) * 16;
	int low = hex_to_int(d);
	return high+low;
}

void printHEX(const char* st)
{
	int length = strlen(st);
	if (length % 2 != 0) {
		printf("%s\n", "invalid hex length");
		return;
	}
	int i;
	char buf = 0;
	for(i = 0; i < length; i++) {
		if(i % 2 != 0)
			printf("%c", hex_to_ascii(buf, st[i]));
		else
		    buf = st[i];
	}
	printf("\n");
}

//going to use this function to calculate our private key
//mathematical formula looks like

//de = 1 mod(p-1)(q-1)

//this is how our final result should be formatted

BIGNUM* cal_rsa_priv_key(BIGNUM* p, BIGNUM* q, BIGNUM* e) {

BN_CTX *ctx = BN_CTX_new();
BIGNUM* p_1 = BN_new();
BIGNUM* q_1 = BN_new();
BIGNUM* one = BN_new();
BIGNUM* rh = BN_new();
BIGNUM* res = BN_new();

BN_dec2bn(&one,"1");

//we need (p-1) and (n-1)
BN_sub(p_1,p,one);
BN_sub(q_1,q,one);

//multiply the two together to gain the righthand side of the equation
BN_mul(rh,p_1,q_1,ctx);

//Now we need our final result
BN_mod_inverse(res,e,rh,ctx);
BN_CTX_free(ctx);
return res;

}

BIGNUM* rsa_encrypt(BIGNUM* message, BIGNUM* mod, BIGNUM* pub_key)
{

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* enc = BN_new();
	BN_mod_exp(enc, message, mod, pub_key, ctx);
	BN_CTX_free(ctx);
	return enc;
}

BIGNUM* rsa_decrypt(BIGNUM* enc, BIGNUM* priv_key, BIGNUM* pub_key)
{

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* dec = BN_new();
	BN_mod_exp(dec, enc, priv_key, pub_key, ctx);
	BN_CTX_free(ctx);
	return dec;
}

int main() {
	// Task 5 //


BIGNUM* t5 = BN_new();
BIGNUM* sig = BN_new();

BN_hex2bn(&t5, "4c61756e63682061206d6973736c652e");
BN_hex2bn(&pbk2, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
BN_hex2bn(&sig, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

//decrypt the message with the public key
decode = rsa_decrypt(sig,mod,pbk2);
printf("the task 5 msg is: ");

printHEX(BN_bn2hex(decode));
printf("\n");

//corrupt the signature by replacing the 2F with a 3F at the end of the signature
BN_hex2bn(&sig,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

//now we are decrypting a corrupted message with the public key
decode = rsa_decrypt(sig,mod,pbk2);
printf("the corrupted message for t5: ");

//should result in a corrupted output
printHEX(BN_bn2hex(decode));
printf("\n");

};