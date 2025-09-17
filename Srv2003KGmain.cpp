/*
 * Windows Server 2003 CD Key Verification/Generator
 * 
 * Based on the original work by z22 for Windows XP and research from "Inside Windows Product Activation".
 * This version is updated to use modern OpenSSL 3.x APIs and fixes various compilation warnings.
 *
 * How to compile with MSYS2/MinGW64:
 * g++ -Wall -Wextra -g3 Srv2003KGmain.cpp -o Srv2003KG.exe -lssl -lcrypto
 */

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h> // Use EVP for modern SHA1 implementation
#include <openssl/rand.h>
#include <assert.h>

// Define types for clarity
typedef unsigned char U8;
typedef unsigned long U32;

// Base24 character set used for encoding/decoding product keys
U8 cset[] = "BCDFGHJKMPQRTVWXY2346789";

// Constants for Server 2003 key structure
#define FIELD_BITS_2003 512
#define FIELD_BYTES_2003 64

/**
 * @brief Unpacks the various parts from the 128-bit binary key data.
 * @param osfamily  [out] 11 bits, the OS family ID.
 * @param hash      [out] 27 bits, part of the hardware hash.
 * @param sig       [out] 58 bits, part of the digital signature.
 * @param prefix    [out] 10 bits, the product ID prefix.
 * @param raw       [in]  128-bit raw binary key data (4 x U32).
 */
void unpack2003(U32 *osfamily, U32 *hash, U32 *sig, U32 *prefix, U32 *raw)
{
	osfamily[0] = raw[0] & 0x7ff;
	hash[0] = ((raw[0] >> 11) | (raw[1] << 21)) & 0x7fffffff;
	sig[0] = (raw[1] >> 10) | (raw[2] << 22);
	sig[1] = ((raw[2] >> 10) | (raw[3] << 22)) & 0x3fffffff;
	prefix[0] = (raw[3] >> 8) & 0x3ff;
}

/**
 * @brief Packs the various parts of the key into 128-bit binary data.
 * @param raw       [out] 128-bit raw binary key data (4 x U32).
 * @param osfamily  [in]  11 bits, the OS family ID.
 * @param hash      [in]  27 bits, part of the hardware hash.
 * @param sig       [in]  58 bits, part of the digital signature.
 * @param prefix    [in]  10 bits, the product ID prefix.
 */
void pack2003(U32 *raw, U32 *osfamily, U32 *hash, U32 *sig, U32 *prefix)
{
	raw[0] = osfamily[0] | (hash[0] << 11);
	raw[1] = (hash[0] >> 21) | (sig[0] << 10);
	raw[2] = (sig[0] >> 22) | (sig[1] << 10);
	raw[3] = (sig[1] >> 22) | (prefix[0] << 8);
}

/**
 * @brief Reverses the byte order of a data buffer (Little-Endian <-> Big-Endian).
 * @param x [in,out] Pointer to the data buffer.
 * @param n [in]     Length of the data buffer.
 */
static void endian(U8 *x, int n)
{
	int i;
	for (i = 0; i < n/2; i++) {
		U8 t;
		t = x[i];
		x[i] = x[n-i-1];
		x[n-i-1] = t;
	}
}

/**
 * @brief Converts a 25-character Base24 encoded key into a 128-bit binary representation.
 * @param x [out] 128-bit binary result (4 x U32).
 * @param c [in]  25-character Base24 encoded data (each char is an index into cset).
 */
void unbase24(U32 *x, U8 *c)
{
	memset(x, 0, 16);
	int i, n;
	
	BIGNUM *y = BN_new();
	BN_zero(y);
	
	for (i = 0; i < 25; i++)
	{
		BN_mul_word(y, 24);
		BN_add_word(y, c[i]);
	}
	n = BN_num_bytes(y);
	BN_bn2bin(y, (U8 *)x);
	BN_free(y);
	
	endian((U8 *)x, n);
}

/**
 * @brief Converts a 128-bit binary data into a 25-character Base24 encoded key.
 * @param c [out] 25-character Base24 encoded result.
 * @param x [in]  128-bit binary data (4 x U32).
 */
void base24(U8 *c, U32 *x)
{
	U8 y[16];
	int i;
	
	BIGNUM *z;
	memcpy(y, x, sizeof(y));
	for (i = 15; y[i] == 0; i--) {} i++;
	endian(y, i);
	z = BN_bin2bn(y, i, NULL);
	
	c[25] = 0;
	for (i = 24; i >= 0; i--) {
		U8 t = BN_div_word(z, 24);
		c[i] = cset[t];
	}
	BN_free(z);
}

/**
 * @brief Prints a formatted product key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX).
 * @param pk [in] A 25-character product key.
 */
void print_product_key(U8 *pk)
{
	int i;
	assert(strlen((const char*)pk) == 25);
	for (i = 0; i < 25; i++) {
		putchar(pk[i]);
		if (i != 24 && i % 5 == 4) putchar('-');
	}
}

/**
 * @brief Calculates a SHA1 hash using the modern EVP API.
 * @param data [in]  Array of pointers to the input data segments.
 * @param data_len [in] Array of lengths for each data segment.
 * @param count [in] Number of data segments.
 * @param md [out] The resulting 20-byte hash.
 * @return 1 on success, 0 on failure.
 */
int sha1_calculate(const U8* data[], const size_t data_len[], int count, U8* md) {
    EVP_MD_CTX *md_ctx;
    const EVP_MD *sha1_md = EVP_sha1();
    unsigned int md_len;

    if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
        return 0;
    }
    if (EVP_DigestInit_ex(md_ctx, sha1_md, NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    for (int i = 0; i < count; ++i) {
        if (EVP_DigestUpdate(md_ctx, data[i], data_len[i]) != 1) {
            EVP_MD_CTX_free(md_ctx);
            return 0;
        }
    }
    if (EVP_DigestFinal_ex(md_ctx, md, &md_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    EVP_MD_CTX_free(md_ctx);
    return 1;
}


/**
 * @brief Verifies the validity of a Server 2003 product key.
 * @param ec          [in] The elliptic curve group.
 * @param generator   [in] The generator point G of the elliptic curve.
 * @param public_key  [in] The public key used for verification.
 * @param cdkey       [in] The 25-character CD-KEY string.
 */
void verify2003(EC_GROUP *ec, EC_POINT *generator, EC_POINT *public_key, char *cdkey)
{
	U8 key[25];
	int i, j;
    size_t k; // Use size_t to match strlen and avoid comparison warnings

	BN_CTX *ctx = BN_CTX_new();
	
    // Remove dashes from the CD-KEY string and convert to Base24 indices
	for (i = 0, k = 0; (size_t)i < strlen(cdkey); i++) {
		for (j = 0; j < 24; j++) {
			if (cdkey[i] != '-' && cdkey[i] == cset[j]) {
				key[k++] = j;
				break;
			}
		}
		if (k >= 25) break;
	}
    if (k < 25) {
        printf("Invalid CD-KEY format.\n");
        BN_CTX_free(ctx);
        return;
    }
	
	U32 bkey[4] = {0};
	U32 osfamily[1], hash[1], sig[2], prefix[1];
	unbase24(bkey, key);
	printf("Binary Key: %.8lx %.8lx %.8lx %.8lx\n", bkey[3], bkey[2], bkey[1], bkey[0]);
	unpack2003(osfamily, hash, sig, prefix, bkey);
	
	printf("OS Family: %lu\nHash: %.8lx\nSig: %.8lx %.8lx\nPrefix: %.8lx\n", osfamily[0], hash[0], sig[1], sig[0], prefix[0]);
	
	U8 buf[FIELD_BYTES_2003], md[20];
	U32 h1[2];
	
	/* h1 = SHA-1(0x5D || OS Family || Hash || Prefix || 00 00) */
    // Prepare data for SHA1 calculation
	buf[0] = 0x5d;
	buf[1] = osfamily[0] & 0xff;
	buf[2] = (osfamily[0] & 0xff00) >> 8;
	buf[3] = hash[0] & 0xff;
	buf[4] = (hash[0] & 0xff00) >> 8;
	buf[5] = (hash[0] & 0xff0000) >> 16;
	buf[6] = (hash[0] & 0xff000000) >> 24;
	buf[7] = prefix[0] & 0xff;
	buf[8] = (prefix[0] & 0xff00) >> 8;
	buf[9] = buf[10] = 0;

    const U8* h1_data[] = {buf};
    const size_t h1_data_len[] = {11};
    sha1_calculate(h1_data, h1_data_len, 1, md);

	h1[0] = md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24);
	h1[1] = (md[4] | (md[5] << 8) | (md[6] << 16) | (md[7] << 24)) >> 2;
	h1[1] &= 0x3FFFFFFF;
	printf("h1: %.8lx %.8lx\n", h1[1], h1[0]);
	
	BIGNUM *s, *h, *x, *y;
	x = BN_new();
	y = BN_new();
	endian((U8 *)sig, 8);
	endian((U8 *)h1, 8);
	s = BN_bin2bn((U8 *)sig, 8, NULL);
	h = BN_bin2bn((U8 *)h1, 8, NULL);

	EC_POINT *r = EC_POINT_new(ec);
	EC_POINT *t = EC_POINT_new(ec);
	/* r = sig*(sig*generator + h1*public_key) */
	EC_POINT_mul(ec, t, NULL, generator, s, ctx);
	EC_POINT_mul(ec, r, NULL, public_key, h, ctx);
	EC_POINT_add(ec, r, r, t, ctx);
	EC_POINT_mul(ec, r, NULL, r, s, ctx);
    // Use non-deprecated API
	EC_POINT_get_affine_coordinates(ec, r, x, y, ctx);
	
	U32 h2[1];
	/* h2 = SHA-1(0x79 || OS Family || r.x || r.y) */
	buf[0] = 0x79;
	buf[1] = osfamily[0] & 0xff;
	buf[2] = (osfamily[0] & 0xff00) >> 8;
	
    U8 bn_buf_x[FIELD_BYTES_2003] = {0};
    U8 bn_buf_y[FIELD_BYTES_2003] = {0};
	BN_bn2bin(x, bn_buf_x);
	endian(bn_buf_x, FIELD_BYTES_2003);
	BN_bn2bin(y, bn_buf_y);
	endian(bn_buf_y, FIELD_BYTES_2003);

    const U8* h2_data[] = {buf, bn_buf_x, bn_buf_y};
    const size_t h2_data_len[] = {3, FIELD_BYTES_2003, FIELD_BYTES_2003};
    sha1_calculate(h2_data, h2_data_len, 3, md);
	
	h2[0] = (md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) & 0x7fffffff;
	printf("Calculated hash: %.8lx\n", h2[0]);
	
	if (h2[0] == hash[0]) printf("Key VALID\n");
	else printf("Key invalid\n");
	
	BN_free(s);
	BN_free(h);
	BN_free(x);
	BN_free(y);
	EC_POINT_free(r);
	EC_POINT_free(t);
	BN_CTX_free(ctx);
}

/**
 * @brief Generates a Server 2003 product key.
 * @param pkey       [out] The generated 25-character product key.
 * @param ec         [in]  The elliptic curve group.
 * @param generator  [in]  The generator point G of the elliptic curve.
 * @param order      [in]  The order of the point G.
 * @param priv       [in]  The private key.
 * @param osfamily   [in]  The OS family ID.
 * @param prefix     [in]  The product ID prefix.
 */
void generate2003(U8 *pkey, EC_GROUP *ec, EC_POINT *generator, BIGNUM *order, BIGNUM *priv, U32 *osfamily, U32 *prefix)
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *k = BN_new();
	BIGNUM *s = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *b = BN_new();
	EC_POINT *r = EC_POINT_new(ec);

	U32 bkey[4];
	U8 buf[FIELD_BYTES_2003], md[20];
	U32 h1[2];
	U32 hash[1], sig[2];
	
	for (;;) {
		/* r = k*generator */
        // Use the recommended random number generation API for OpenSSL 3.0
		BN_rand(k, FIELD_BITS_2003, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
		EC_POINT_mul(ec, r, NULL, generator, k, ctx);
        // Use non-deprecated API
		EC_POINT_get_affine_coordinates(ec, r, x, y, ctx);
			
		/* hash = SHA-1(0x79 || OS Family || r.x || r.y) */
		buf[0] = 0x79;
		buf[1] = osfamily[0] & 0xff;
		buf[2] = (osfamily[0] & 0xff00) >> 8;

        U8 bn_buf_x[FIELD_BYTES_2003] = {0};
        U8 bn_buf_y[FIELD_BYTES_2003] = {0};
        BN_bn2bin(x, bn_buf_x);
        endian(bn_buf_x, FIELD_BYTES_2003);
        BN_bn2bin(y, bn_buf_y);
        endian(bn_buf_y, FIELD_BYTES_2003);

        const U8* hash_data[] = {buf, bn_buf_x, bn_buf_y};
        const size_t hash_data_len[] = {3, FIELD_BYTES_2003, FIELD_BYTES_2003};
        sha1_calculate(hash_data, hash_data_len, 3, md);

		hash[0] = (md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) & 0x7fffffff;
			
		/* h1 = SHA-1(0x5D || OS Family || Hash || Prefix || 00 00) */
		buf[0] = 0x5d;
		buf[1] = osfamily[0] & 0xff;
		buf[2] = (osfamily[0] & 0xff00) >> 8;
		buf[3] = hash[0] & 0xff;
		buf[4] = (hash[0] & 0xff00) >> 8;
		buf[5] = (hash[0] & 0xff0000) >> 16;
		buf[6] = (hash[0] & 0xff000000) >> 24;
		buf[7] = prefix[0] & 0xff;
		buf[8] = (prefix[0] & 0xff00) >> 8;
		buf[9] = buf[10] = 0;

        const U8* h1_data[] = {buf};
        const size_t h1_data_len[] = {11};
        sha1_calculate(h1_data, h1_data_len, 1, md);

		h1[0] = md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24);
		h1[1] = (md[4] | (md[5] << 8) | (md[6] << 16) | (md[7] << 24)) >> 2;
		h1[1] &= 0x3FFFFFFF;
		printf("h1: %.8lx %.8lx\n", h1[1], h1[0]);
	
		/* s = ( -h1*priv + sqrt( (h1*priv)^2 + 4k ) ) / 2 */
		endian((U8 *)h1, 8);
		BN_bin2bn((U8 *)h1, 8, b);
		BN_mod_mul(b, b, priv, order, ctx);
		BN_copy(s, b);
		BN_mod_sqr(s, s, order, ctx);
		BN_lshift(k, k, 2);
		BN_add(s, s, k);
		BN_mod_sqrt(s, s, order, ctx);
		BN_mod_sub(s, s, b, order, ctx);
		if (BN_is_odd(s)) {
			BN_add(s, s, order);
		}
		BN_rshift1(s, s);
		sig[0] = sig[1] = 0;
		BN_bn2bin(s, (U8 *)sig);
		endian((U8 *)sig, BN_num_bytes(s));
		if (sig[1] < 0x40000000) break;
	}
	pack2003(bkey, osfamily, hash, sig, prefix);
	printf("OS family: %lu\nHash: %.8lx\nSig: %.8lx %.8lx\nPrefix: %.8lx\n", osfamily[0], hash[0], sig[1], sig[0], prefix[0]);
	printf("Binary Key: %.8lx %.8lx %.8lx %.8lx\n", bkey[3], bkey[2], bkey[1], bkey[0]);
	base24(pkey, bkey);
	
	BN_free(k);
	BN_free(s);
	BN_free(x);
	BN_free(y);
	BN_free(b);
	EC_POINT_free(r);

	BN_CTX_free(ctx);
	
}

int main()
{
	BIGNUM *a, *b, *p, *gx, *gy, *pubx, *puby, *n, *priv;
	BN_CTX *ctx = BN_CTX_new();
	
	a = BN_new();
	b = BN_new();
	p = BN_new();
	gx = BN_new();
	gy = BN_new();
	pubx = BN_new();
	puby = BN_new();
	n = BN_new();
	priv = BN_new();

	/* Windows Sever 2003 VLK */
	BN_set_word(a, 1);
	BN_set_word(b, 0);
	BN_hex2bn(&p,    "C9AE7AED19F6A7E100AADE98134111AD8118E59B8264734327940064BC675A0C682E19C89695FBFA3A4653E47D47FD7592258C7E3C3C61BBEA07FE5A7E842379");
	BN_hex2bn(&gx,   "85ACEC9F9F9B456A78E43C3637DC88D21F977A9EC15E5225BD5060CE5B892F24FEDEE574BF5801F06BC232EEF2161074496613698D88FAC4B397CE3B475406A7");
	BN_hex2bn(&gy,   "66B7D1983F5D4FE43E8B4F1E28685DE0E22BBE6576A1A6B86C67533BF72FD3D082DBA281A556A16E593DB522942C8DD7120BA50C9413DF944E7258BDDF30B3C4");
	BN_hex2bn(&pubx, "90BF6BD980C536A8DB93B52AA9AEBA640BABF1D31BEC7AA345BB7510194A9B07379F552DA7B4A3EF81A9B87E0B85B5118E1E20A098641EE4CCF2045558C98C0E");
	BN_hex2bn(&puby, "6B87D1E658D03868362945CDD582E2CF33EE4BA06369E0EFE9E4851F6DCBEC7F15081E250D171EA0CC4CB06435BCFCFEA8F438C9766743A06CBD06E7EFB4C3AE");
	BN_hex2bn(&n,    "4CC5C56529F0237D"); // from mskey 4in1
	BN_hex2bn(&priv, "2606120F59C05118");
	
	
	EC_GROUP *ec = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	EC_POINT *g = EC_POINT_new(ec);
    // Use non-deprecated API
	EC_POINT_set_affine_coordinates(ec, g, gx, gy, ctx);
	EC_POINT *pub = EC_POINT_new(ec);
    // Use non-deprecated API
	EC_POINT_set_affine_coordinates(ec, pub, pubx, puby, ctx);
	
	assert(EC_POINT_is_on_curve(ec, g, ctx) == 1);
	assert(EC_POINT_is_on_curve(ec, pub, ctx) == 1);
	
	U8 pkey[25];
	U32 osfamily[1], prefix[1];
	
	osfamily[0] = 1280; // Server 2003 Family ID
    // Use the recommended random number generation API for OpenSSL 3.0
    if (RAND_bytes((U8 *)prefix, 4) != 1) {
        printf("Error generating random bytes.\n");
        // Cleanup before exit
        BN_CTX_free(ctx);
        // Free other BIGNUMs and EC points
        return 1;
    }
	prefix[0] &= 0x3ff; // Prefix is 10 bits
	generate2003(pkey, ec, g, n, priv, osfamily, prefix);
	print_product_key(pkey); printf("\n\n");
	verify2003(ec, g, pub, (char*)pkey);

	BN_CTX_free(ctx);
	
	return 0;
}
