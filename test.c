#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "test-vectors.h"

#if OPENSSL_VERSION_NUMBER < 0x10101000L
# error "OpenSSL version does not support EdDSA."
#endif

int
main(void)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *ctx;
	EVP_PKEY *pkey;
	const struct test_vector *t;
	unsigned char *msg, *pub, *sig;
	size_t msglen, publen, siglen;
	int rc, i;

	for (t = tests, i = 0;  t->pub && t->sig; t++, i++) {
		msg = (unsigned char *)t_msg;
		msglen = strlen(t_msg);
		pub = OPENSSL_hexstr2buf(t->pub, (long *)&publen);
		assert(msg != pub);
		sig = OPENSSL_hexstr2buf(t->sig, (long *)&siglen);
		assert(sig != pub);
		ctx = EVP_MD_CTX_new();
		assert(ctx != NULL);

		pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
						   NULL, pub, publen);
		assert(pkey != NULL);

		rc = EVP_DigestVerifyInit(ctx, &pctx, NULL, NULL, pkey);
		assert(rc == 1);

		rc = EVP_DigestVerify(ctx, sig, siglen, msg, msglen);
		if (rc == 0)
			fprintf(stderr, "Verify test %d: fail.\n", i);
		else if (rc == 1)
			fprintf(stderr, "Verify test %d: success.\n", i);
		else
			assert("Some error" == NULL);

		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(pub);
		free(sig);

	}
	return 0;
}
