/* FIGARO'S PASSWORD MANAGER 2 (FPM2)
 * Copyright (C) 2000 John Conneely
 * Copyright (C) 2009-2025 Aleš Koval
 *
 * FPM is open source / free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * FPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 * This file contains the crypto interface for FPM.
 *
 * fpm_crypt.c - Crypto interface for FPM
 */

#include <gtk/gtk.h>
#include <stdlib.h>

#include "fpm_crypt.h"
#include "fpm_nettle.h"
#include "fpm.h"

#include <nettle/pbkdf2.h>
#include <nettle/aes.h>
#include <nettle/yarrow.h>
#include <nettle/gcm.h>
#include <nettle/eax.h>
#include <nettle/chacha-poly1305.h>

fpm_crypto_context *crypto;
fpm_cipher_algo cipher_algo;

void (*fpm_setkey) (fpm_cipher *cipher, const byte *key);
void (*fpm_encrypt_block) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf);
void (*fpm_decrypt_block) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf);
void (*fpm_decrypt_data) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void (*fpm_encrypt_data) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);

void (*fpm_set_iv) (fpm_cipher *cipher, byte *iv);
void (*fpm_get_tag) (fpm_cipher *cipher, gsize len, byte *tag);
void (*fpm_add_data) (fpm_cipher *cipher, gsize len, byte *data);

static const fpm_cipher_info ciphers[] = {
    { "AES-256", AES_BLOCK_SIZE, AES256_KEY_SIZE, 0, sizeof(struct aes256_ctx), 0 },
    { "AES-256-GCM", GCM_BLOCK_SIZE, AES256_KEY_SIZE, GCM_DIGEST_SIZE, sizeof(struct gcm_aes256_ctx), FPM_IV_SIZE },
    { "AES-128-EAX", EAX_BLOCK_SIZE, AES128_KEY_SIZE, EAX_DIGEST_SIZE, sizeof(struct eax_aes128_ctx), FPM_IV_SIZE },
    { "ChaCha-Poly1305", CHACHA_POLY1305_BLOCK_SIZE, CHACHA_POLY1305_KEY_SIZE, CHACHA_POLY1305_DIGEST_SIZE, sizeof(struct chacha_poly1305_ctx), FPM_IV_SIZE },
    { "Camellia256-GCM", GCM_BLOCK_SIZE, CAMELLIA256_KEY_SIZE, GCM_DIGEST_SIZE, sizeof(struct gcm_camellia256_ctx), FPM_IV_SIZE }
};

static void fpm_hex_to_bin(byte* out, const gchar* in, gint len);
static void fpm_bin_to_hex(gchar* out, const byte* in, gint len);

fpm_cipher_algo fpm_get_cipher_algo (gchar *cipher_name) {
    for (gsize i = 0; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
	if (strcmp (cipher_name, ciphers[i].name) == 0)
	    return (i);
    return CIPHER_UNKNOWN;
}

GList *fpm_get_ciphers(void) {
    GList *ciphers_list = NULL;

    for (gsize i = 1; i < sizeof (ciphers) / sizeof (ciphers[0]); i++)
	ciphers_list = g_list_append (ciphers_list, ciphers[i].name);

    return ciphers_list;
}

void fpm_cipher_init(char *cipher_name) {

    cipher_algo = fpm_get_cipher_algo (cipher_name);

    switch(cipher_algo)  {

	case AES256:
		fpm_setkey = aes256_set_key;
		fpm_decrypt_data = aes256_decrypt_data;
		fpm_encrypt_data = aes256_encrypt_data;
		break;

	case AES256_GCM:
		fpm_setkey = aes256_gcm_set_key;
		fpm_decrypt_data = aes256_gcm_decrypt_data;
		fpm_encrypt_data = aes256_gcm_encrypt_data;
		fpm_set_iv = aes256_gcm_set_iv;
		fpm_get_tag = aes256_gcm_get_tag;
		fpm_add_data = aes256_gcm_add_data;
		break;

	case AES128_EAX:
		fpm_setkey = aes128_eax_set_key;
		fpm_decrypt_data = aes128_eax_decrypt_data;
		fpm_encrypt_data = aes128_eax_encrypt_data;
		fpm_set_iv = aes128_eax_set_iv;
		fpm_get_tag = aes128_eax_get_tag;
		fpm_add_data = aes128_eax_add_data;
		break;

	case ChaCha_Poly1305:
		fpm_setkey = chacha_poly1305_set_key_wrap;
		fpm_decrypt_data = chacha_poly1305_decrypt_data;
		fpm_encrypt_data = chacha_poly1305_encrypt_data;
		fpm_set_iv = chacha_poly1305_set_iv;
		fpm_get_tag = chacha_poly1305_get_tag;
		fpm_add_data = chacha_poly1305_add_data;
		break;

	case Camellia256_GCM:
		fpm_setkey = camellia256_gcm_set_key;
		fpm_decrypt_data = camellia256_gcm_decrypt_data;
		fpm_encrypt_data = camellia256_gcm_encrypt_data;
		fpm_set_iv = camellia256_gcm_set_iv;
		fpm_get_tag = camellia256_gcm_get_tag;
		fpm_add_data = camellia256_gcm_add_data;
		break;

	default:
		printf("Unknown cipher algorithm!\n");
		exit(-1);
    }

    crypto->cipher_info = &ciphers[cipher_algo];

    crypto->old = g_malloc (sizeof (fpm_cipher));
    crypto->new = g_malloc (sizeof (fpm_cipher));

    crypto->old->context = g_malloc (crypto->cipher_info->contextsize);
    crypto->new->context = g_malloc (crypto->cipher_info->contextsize);

    crypto->iv = g_malloc (crypto->cipher_info->ivsize);

    FILE* rnd;
    byte *buf = g_malloc (YARROW256_SEED_FILE_SIZE);
    rnd = fopen ("/dev/random", "r");
    gint ret __attribute__((unused)) = fread(buf, 1, YARROW256_SEED_FILE_SIZE, rnd);
    fclose (rnd);

    crypto->rnd = g_malloc (sizeof (struct yarrow256_ctx));
    yarrow256_init (crypto->rnd, 0, NULL);
    yarrow256_seed (crypto->rnd, YARROW256_SEED_FILE_SIZE, buf);
    g_free (buf);
}

void fpm_crypt_init (gchar *password) {
    byte *hash_1, *hash_2;

    hash_1 = g_malloc (FPM_HASH_SIZE);
    hash_2 = g_malloc (FPM_HASH_SIZE);

    pbkdf2_hmac_sha256 (strlen (password), (byte *)password, crypto->kdf_iterations, FPM_SALT_SIZE, crypto->old->salt, FPM_HASH_SIZE, hash_1);
    pbkdf2_hmac_sha256 (strlen (password), (byte *)password, crypto->kdf_iterations, FPM_SALT_SIZE, crypto->new->salt, FPM_HASH_SIZE, hash_2);

    fpm_setkey (crypto->old, hash_1);
    fpm_setkey (crypto->new, hash_2);

    wipememory (hash_1, FPM_HASH_SIZE);
    wipememory (hash_2, FPM_HASH_SIZE);

    g_free (hash_1);
    g_free (hash_2);
}

void fpm_crypt_set_password (gchar *password) {
    byte *hash;

    crypto->new->salt = fpm_get_new_salt (FPM_SALT_SIZE);
    hash = g_malloc (FPM_HASH_SIZE);

    pbkdf2_hmac_sha256 (strlen (password), (byte *)password, crypto->kdf_iterations, FPM_SALT_SIZE, crypto->new->salt, FPM_HASH_SIZE, hash);

    fpm_setkey(crypto->new, hash);

    wipememory(hash, FPM_HASH_SIZE);
    g_free(hash);
}

static void
fpm_addnoise(gchar* field, gint len)
{
  /* If we have a short string, I add noise after the first null prior
   * to encrypting.  This prevents empty blocks from looking identical
   * to eachother in the encrypted file.  rnd() is probably good enough
   * for this... no need to decrease entrophy in /dev/random.
   */
  gint i;
  gboolean gotit=FALSE;

  for(i=0;i<len;i++)
    if (gotit)
    {
      field[i]=(char)(256.0*rand()/(RAND_MAX+1.0));
    }
    else if (field[i]=='\00')
    {
        gotit=TRUE;
    }
}

static void
fpm_rotate(gchar* field, gsize len)
{
  /* After we use addnoise (above) we ensure blocks don't look identical
   * unless all 8 chars in the block are part of the password.  This
   * routine makes us use all three blocks equally rather than fill the
   * first, then the second, etc.   This makes it so none of the blocks
   * in the password will remain constant from save to save, even if the
   * password is from 7-20 characters long.  Note that passwords from
   * 21-24 characters start to fill blocks, and so will be constant.
   */

  gint num_blocks;
  gchar* tmp;
  gint b;
  gsize i;

  g_assert(crypto->cipher_info->blocksize > 0);
  num_blocks = len/crypto->cipher_info->blocksize;

  g_assert(len==num_blocks * crypto->cipher_info->blocksize);
  tmp=g_malloc0(len+1);
  for(b=0;b<num_blocks;b++)
  {
    for(i=0;i< crypto->cipher_info->blocksize;i++) tmp[b* crypto->cipher_info->blocksize + i] = field[i*num_blocks+b];
  }
  memcpy(field, tmp, len);
  wipememory(tmp, len);
  g_free(tmp);
}

static void
fpm_unrotate(gchar* field, gsize len)
{
  gint num_blocks;
  gchar* tmp;
  gint b;
  gsize i;

  g_assert(crypto->cipher_info->blocksize>0);
  num_blocks = len/crypto->cipher_info->blocksize;
  g_assert(len==num_blocks*crypto->cipher_info->blocksize);
  tmp=g_malloc0(len+1);
  for(b=0;b<num_blocks;b++)
  {
    for(i=0;i<crypto->cipher_info->blocksize;i++) tmp[i*num_blocks+b] = field[b*crypto->cipher_info->blocksize+i];
  }
  memcpy(field, tmp, len);
  wipememory(tmp, len);
  g_free(tmp);
}

void
fpm_decrypt_field(	fpm_cipher *cipher,
		  	gchar* plaintext,
			gchar* cipher_field,
			gsize len)
{
  byte* ciphertext;

  g_assert(strlen(cipher_field)==2*len);

  ciphertext = g_malloc(len);
  fpm_hex_to_bin(ciphertext, cipher_field, len);

  fpm_decrypt_data (cipher, (byte *)plaintext, ciphertext, len);

  fpm_unrotate(plaintext, len);

  g_free(ciphertext);
}

gchar*
fpm_decrypt_field_var(  fpm_cipher *cipher,
			gchar* cipher_field)
{
  gint len;
  gchar *plaintext;

  len = strlen(cipher_field);
  len = len / 2;

  plaintext = g_malloc0(len + 1); 

  fpm_decrypt_field(cipher, plaintext, cipher_field, len); 

  return(plaintext);
}

void
fpm_encrypt_field(	fpm_cipher *cipher,
			gchar* cipher_field,
			gchar* plaintext,
			gsize len)
{
  byte *ciphertext;

  fpm_addnoise(plaintext, len);
  fpm_rotate(plaintext, len);

  ciphertext = g_malloc(len);

  fpm_encrypt_data(cipher, ciphertext, (byte *)plaintext, len);

  fpm_bin_to_hex(cipher_field, ciphertext, len);
  g_free(ciphertext);
}

gchar*
fpm_encrypt_field_var(	fpm_cipher *cipher,
                        gchar* plaintext)
{
  gint num_blocks, len;
  gchar* cipher_field;
  gchar* plain_field;

  num_blocks = (strlen(plaintext)/(crypto->cipher_info->blocksize-1))+1;
  len = num_blocks*crypto->cipher_info->blocksize;
  plain_field = g_malloc0(len+1);
  strncpy(plain_field, plaintext, len);
  cipher_field = g_malloc0((len*2)+1);

  fpm_encrypt_field(cipher, cipher_field, plain_field, num_blocks*crypto->cipher_info->blocksize);

  wipememory(plain_field, len);
  g_free(plain_field);

  return(cipher_field);
}

static void fpm_hex_to_bin(byte* out, const gchar* in, gint len)
{
  gint i, high, low;
  byte data;

  for(i=0; i<len; i++)
  {
    high=in[2*i]-'a';
    low=in[2*i+1]-'a';
    data = high*16+low;
    out[i]=data;
  }
}

static void fpm_bin_to_hex(gchar* out, const byte* in, gint len)
{
  gint i, high, low;
  byte data;

  for(i=0; i<len; i++)
  {
    data = in[i];
    high=data/16;
    low = data - high*16;
    out[2*i]='a'+high;
    out[2*i+1]='a'+low;
  }
}

/* Legacy salt */
gchar* get_new_salt(gint len)
{
  byte* data;
  gchar* ret_val;
  gint ret __attribute__((unused));
  FILE* rnd;

  data = g_malloc0(len+1);
  ret_val = g_malloc0(len*2+1);
  rnd = fopen("/dev/urandom", "r");

  ret = fread(data, 1, len, rnd);
  fpm_bin_to_hex(ret_val, data, len);
  fclose(rnd);
  g_free(data);
  return(ret_val);
}

byte* fpm_get_new_salt (gsize len) {
    byte *data;

    data = g_malloc (len);
    yarrow256_random (crypto->rnd, FPM_SALT_SIZE, data);
    return (data);
}

byte* fpm_get_new_iv (void) {
    byte *data;

    data = g_malloc (crypto->cipher_info->ivsize);
    yarrow256_random (crypto->rnd, crypto->cipher_info->ivsize, data);
    return (data);
}

static void fpm_decrypt_field_inplace(gchar** text_ptr)
{
  gchar* old_text;
  gchar* new_text;

  old_text = *text_ptr;
  new_text = fpm_decrypt_field_var(crypto->old, old_text);
  g_free(old_text);
  *text_ptr=new_text;
}


void fpm_decrypt_all(void)
{
  GList *list;
  fpm_data *data;

  list = g_list_first(glb_pass_list);
  while(list != NULL)
  {
    data = list->data;
    fpm_decrypt_field_inplace(&data->title);
    fpm_decrypt_field_inplace(&data->arg);
    fpm_decrypt_field_inplace(&data->user);
    fpm_decrypt_field_inplace(&data->notes);
    fpm_decrypt_field_inplace(&data->category);
    fpm_decrypt_field_inplace(&data->launcher);

    list=g_list_next(list);
  }
}

void fpm_decrypt_launchers(void) {
  GList *list;
  fpm_launcher *data;
  gchar* plaintext;

  list = g_list_first(glb_launcher_list);
  while(list != NULL)
  {
    data = list->data;
    fpm_decrypt_field_inplace (&data->title);
    fpm_decrypt_field_inplace (&data->cmdline);

    plaintext = fpm_decrypt_field_var (crypto->old, data->c_user);
    data->copy_user = atoi (plaintext);

    plaintext = fpm_decrypt_field_var(crypto->old, data->c_pass);
    data->copy_password = atoi(plaintext);
    g_free(data->c_pass);

    list = g_list_next(list);
  }
}

gchar* fpm_encrypt_data_base64 (fpm_cipher *cipher, byte *plaintext, gsize len) {
    byte *ciphertext;
    gchar *ret_val;

    ciphertext = g_malloc (len);

    fpm_encrypt_data (cipher, ciphertext, plaintext, len);
    ret_val = g_base64_encode (ciphertext, len);

    g_free (ciphertext);

    return (ret_val);
}

gchar* fpm_decrypt_data_base64 (fpm_cipher *cipher, gchar *ciphertext) {
    byte *ciphertext_data;
    byte *ret_val;
    gsize out_len;

    ciphertext_data = g_base64_decode (ciphertext, &out_len);

    ret_val = g_malloc0 (out_len + 1);
    fpm_decrypt_data (cipher, ret_val, ciphertext_data, out_len);
    g_free(ciphertext_data);

    return ((gchar *)ret_val);
}

/* Calculate sha256 hash of file, return 0 for success */
gint fpm_sha256_file(gchar *filename, guchar *digest) {
    FILE *fp;
    GChecksum *checksum;
    gsize size = SHA256_DIGEST_LENGTH;
    guchar buf[1024];
    gulong br;
    gint ret_val = -1;

    checksum = g_checksum_new(G_CHECKSUM_SHA256);

    if((fp = fopen(filename, "r")) != NULL) {
	while ((br = fread (buf, sizeof (guchar), 1024, fp)) > 0) {
	    g_checksum_update(checksum, buf, br);
        }
	if(!ferror(fp)) {
	    g_checksum_get_digest(checksum, digest, &size);
	    g_checksum_free(checksum);
	    ret_val = 0;
	}
        fclose(fp);
    }

    return(ret_val);
}

/* Calculate sha256 hash from all fpm_data entries except passwords */
void fpm_sha256_fpm_data(gchar *digest) {
  GChecksum *checksum;
  gsize size = SHA256_DIGEST_LENGTH;
  GList *list;
  fpm_data *data;
  gchar *buf;

  checksum = g_checksum_new(G_CHECKSUM_SHA256);

  list = g_list_first(glb_pass_list);
  while(list != NULL) {
    data = list->data;
    buf = g_strdup_printf("%s%s%s%s%s%s", data->title, data->arg,
	data->user, data->notes, data->category, data->launcher);
    g_checksum_update(checksum, (guchar *)buf, strlen(buf));
    list = g_list_next(list);
    g_free(buf);
  }
  g_checksum_get_digest(checksum, (guchar *)digest, &size);
  g_checksum_free(checksum);
}
