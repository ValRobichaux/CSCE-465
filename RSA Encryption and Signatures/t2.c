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
	// TASK 2 //

//assign private key
BIGNUM* pk2 = BN_new();
BN_hex2bn(&pk2, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

//assign public key
BIGNUM* pbk2 = BN_new();
BN_hex2bn(&pbk2, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
printBN("the public key is: ", pbk2);
printf("\n");

BIGNUM* mod = BN_new();
BN_hex2bn(&mod, "010001");

// message -> hex -> bignum
BIGNUM* message = BN_new();
BN_hex2bn(&message, "4120746f702073656372657421");

printBN("Task 2 Message:", message);
printf("\n");

BIGNUM* encode = BN_new();
encode = rsa_encrypt(message,mod,pbk2);
printBN("the encrypted message for T2:" , encode);
printf("\n");

BIGNUM* decode = BN_new();
decode = rsa_decrypt(encode,pk2,pbk2);
printf("decrypted message for T2:");
printHEX(BN_bn2hex(decode));
printf("\n");
};