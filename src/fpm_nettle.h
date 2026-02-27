/* FIGARO'S PASSWORD MANAGER 2 (FPM2)
 * Copyright (C) 2016 Aleš Koval
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
 * fpm_nettle.h --- Interface between FPM2 and nettle
 *
 */

void aes256_set_key (fpm_cipher *cipher, const byte *key);
void aes256_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void aes256_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);

void aes256_gcm_set_key (fpm_cipher *cipher, const byte *key);
void aes256_gcm_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void aes256_gcm_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void aes256_gcm_set_iv (fpm_cipher *cipher, byte *iv);
void aes256_gcm_get_tag (fpm_cipher *cipher, gsize len, byte *tag);
void aes256_gcm_add_data (fpm_cipher *cipher, gsize len, byte *data);

void aes128_eax_set_key (fpm_cipher *cipher, const byte *key);
void aes128_eax_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void aes128_eax_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void aes128_eax_set_iv (fpm_cipher *cipher, byte *iv);
void aes128_eax_get_tag (fpm_cipher *cipher, gsize len, byte *tag);
void aes128_eax_add_data (fpm_cipher *cipher, gsize len, byte *data);

void chacha_poly1305_set_key_wrap (fpm_cipher *cipher, const byte *key);
void chacha_poly1305_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void chacha_poly1305_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void chacha_poly1305_set_iv (fpm_cipher *cipher, byte *iv);
void chacha_poly1305_get_tag (fpm_cipher *cipher, gsize len, byte *tag);
void chacha_poly1305_add_data (fpm_cipher *cipher, gsize len, byte *data);

void camellia256_gcm_set_key (fpm_cipher *cipher, const byte *key);
void camellia256_gcm_decrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void camellia256_gcm_encrypt_data (fpm_cipher *cipher, byte *outbuf, const byte *inbuf, gsize len);
void camellia256_gcm_set_iv (fpm_cipher *cipher, byte *iv);
void camellia256_gcm_get_tag (fpm_cipher *cipher, gsize len, byte *tag);
void camellia256_gcm_add_data (fpm_cipher *cipher, gsize len, byte *data);
