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
 *
 * fpm_crypt.h
 */

#include <gtk/gtk.h>

typedef guint8 byte;

#define FPM_DEFAULT_CIPHER "AES-256-GCM"
//#define FPM_DEFAULT_CIPHER "Camellia256-GCM"
//#define FPM_DEFAULT_CIPHER "AES-128-EAX"
//#define FPM_DEFAULT_CIPHER "ChaCha-Poly1305"

#define PBKDF2_ITERATIONS_DEFAULT 600000
#define PBKDF2_ITERATIONS_DEFAULT_OLD 8192

#define SHA256_DIGEST_LENGTH 32

#define FPM_HASH_SIZE	32
#define FPM_SALT_SIZE	16

typedef enum {
    CIPHER_UNKNOWN = -1,
    AES256,
    AES256_GCM,
    AES128_EAX,
    ChaCha_Poly1305,
    Camellia256_GCM
} fpm_cipher_algo;

typedef enum {
    PBKDF2
} fpm_kdf_type;

typedef struct {
    gchar *name;
    gsize blocksize;
    gsize keylen;
    gsize digestsize;
    gsize contextsize;
    gsize ivsize;
} fpm_cipher_info;

typedef struct {
    gpointer context;
    guint8 *salt;
    gboolean decryption_prepared;
} fpm_cipher;

typedef struct {
    const fpm_cipher_info *cipher_info;
    fpm_cipher *old;
    fpm_cipher *new;
    gpointer rnd;
    guint8 *iv;
    fpm_kdf_type kdf;
    guint32 kdf_iterations;
} fpm_crypto_context;

extern fpm_crypto_context *crypto;
extern fpm_cipher_algo cipher_algo;		/* Current cipher algorithm */

GList *fpm_get_ciphers ();
fpm_cipher_algo fpm_get_cipher_algo (gchar *cipher_name);

void fpm_crypt_init (gchar *password);

extern void (*fpm_setkey) (fpm_cipher *cipher, const byte *key);
extern void (*fpm_encrypt_block) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf);
extern void (*fpm_decrypt_block) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf);
extern void (*fpm_decrypt_data) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
extern void (*fpm_encrypt_data) (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);

extern void (*fpm_set_iv) (fpm_cipher *cipher, byte *iv);
extern void (*fpm_get_tag) (fpm_cipher *cipher, gsize len, byte *tag);
extern void (*fpm_add_data) (fpm_cipher *cipher, gsize len, byte *data);

gchar *get_new_salt (gint len);

void fpm_decrypt_field (fpm_cipher *cipher, gchar *plaintext, gchar *cipher_field, gsize len);
void fpm_encrypt_field (fpm_cipher *cipher, gchar *cipher_field, gchar *plaintext, gsize len);

gchar *fpm_encrypt_field_var (fpm_cipher *cipher, gchar *plaintext);
gchar *fpm_decrypt_field_var (fpm_cipher *cipher, gchar *cipher_field);

void fpm_decrypt_all (void);

void fpm_cipher_init (char *cipher);

void fpm_crypt_set_password (gchar *password);

void fpm_decrypt_launchers();

byte *fpm_get_new_iv();
byte *fpm_get_new_salt (gsize len);

gchar *fpm_encrypt_data_base64 (fpm_cipher *cipher, byte *plaintext, gsize len);
gchar *fpm_decrypt_data_base64 (fpm_cipher *cipher, gchar *ciphertext);

void fpm_sha256_fpm_data (gchar *digest);
gint fpm_sha256_file (gchar *filename, guchar *digest);
