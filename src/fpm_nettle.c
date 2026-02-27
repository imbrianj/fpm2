/* FIGARO'S PASSWORD MANAGER 2 (FPM2)
 * Copyright (C) 2016-2025 Aleš Koval
 *
 * FPM2 is open source / free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * FPM2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * fpm_nettle.c --- Interface between FPM2 and nettle
 *
 */

#include "fpm_crypt.h"
#include "fpm_nettle.h"

#include <nettle/aes.h>
#include <nettle/yarrow.h>
#include <nettle/gcm.h>
#include <nettle/eax.h>
#include <nettle/chacha-poly1305.h>

/* AES-256 function for compatibility */
void aes256_set_key (fpm_cipher *cipher, const byte *key) {
    aes256_set_encrypt_key (cipher->context, key);
    cipher->decryption_prepared = FALSE;
}

void aes256_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    if (!cipher->decryption_prepared) {
        aes256_invert_key (cipher->context, cipher->context);
        cipher->decryption_prepared = TRUE;
    }
    aes256_decrypt (cipher->context, len, outbuf, inbuf);
}

void aes256_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    if (cipher->decryption_prepared) {
        /* Rotate all subkey for encrypt */
        aes256_invert_key (cipher->context, cipher->context);
        aes256_invert_key (cipher->context, cipher->context);
        aes256_invert_key (cipher->context, cipher->context);
        cipher->decryption_prepared = FALSE;
    }

    aes256_encrypt (cipher->context, len, outbuf, inbuf);
}

/* AES-256-GCM */
void aes256_gcm_set_key (fpm_cipher *cipher, const byte *key) {
    gcm_aes256_set_key (cipher->context, key);
}

void aes256_gcm_set_iv (fpm_cipher *cipher, byte *iv) {
    gcm_aes256_set_iv (cipher->context, crypto->cipher_info->ivsize, iv);
}

void aes256_gcm_get_tag (fpm_cipher *cipher, gsize len, byte *tag) {
    gcm_aes256_digest (cipher->context, len, tag);
}

void aes256_gcm_add_data (fpm_cipher *cipher, gsize len, byte *data) {
    gcm_aes256_update (cipher->context, len, data);
}

void aes256_gcm_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    gcm_aes256_decrypt (cipher->context, len, outbuf, inbuf);
}

void aes256_gcm_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    gcm_aes256_encrypt (cipher->context, len, outbuf, inbuf);
}

/* AES-128-EAX */
void aes128_eax_set_key (fpm_cipher *cipher, const byte *key) {
    eax_aes128_set_key (cipher->context, key);
}

void aes128_eax_set_iv (fpm_cipher *cipher, byte *iv) {
    eax_aes128_set_nonce (cipher->context, crypto->cipher_info->ivsize, iv);
}

void aes128_eax_get_tag (fpm_cipher *cipher, gsize len, byte *tag) {
    eax_aes128_digest (cipher->context, len, tag);
}

void aes128_eax_add_data (fpm_cipher *cipher, gsize len, byte *data) {
    eax_aes128_update (cipher->context, len, data);
}

void aes128_eax_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    eax_aes128_decrypt (cipher->context, len, outbuf, inbuf);
}

void aes128_eax_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    eax_aes128_encrypt (cipher->context, len, outbuf, inbuf);
}

/* ChaCha-Poly1305 */
void chacha_poly1305_set_key_wrap (fpm_cipher *cipher, const byte *key) {
    chacha_poly1305_set_key (cipher->context, key);
}

void chacha_poly1305_set_iv (fpm_cipher *cipher, byte *iv) {
    chacha_poly1305_set_nonce (cipher->context, iv);
}

void chacha_poly1305_get_tag (fpm_cipher *cipher, gsize len, byte *tag) {
    chacha_poly1305_digest (cipher->context, len, tag);
}

void chacha_poly1305_add_data (fpm_cipher *cipher, gsize len, byte *data) {
    chacha_poly1305_update (cipher->context, len, data);
}

void chacha_poly1305_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    chacha_poly1305_decrypt (cipher->context, len, outbuf, inbuf);
}

void chacha_poly1305_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    chacha_poly1305_encrypt (cipher->context, len, outbuf, inbuf);
}

/* Camellia256-GCM */
void camellia256_gcm_set_key (fpm_cipher *cipher, const byte *key) {
    gcm_camellia256_set_key (cipher->context, key);
}

void camellia256_gcm_set_iv (fpm_cipher *cipher, byte *iv) {
    gcm_camellia256_set_iv (cipher->context, crypto->cipher_info->ivsize, iv);
}

void camellia256_gcm_get_tag (fpm_cipher *cipher, gsize len, byte *tag) {
    gcm_camellia256_digest (cipher->context, len, tag);
}

void camellia256_gcm_add_data (fpm_cipher *cipher, gsize len, byte *data) {
    gcm_camellia256_update (cipher->context, len, data);
}

void camellia256_gcm_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    gcm_camellia256_decrypt (cipher->context, len, outbuf, inbuf);
}

void camellia256_gcm_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len) {
    gcm_camellia256_encrypt (cipher->context, len, outbuf, inbuf);
}
