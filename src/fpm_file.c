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
 * fpm_file.c formerly passfile.c -- Routines to save and load XML files with FPM data.
 */

#include <gtk/gtk.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "fpm.h"
#include "fpm_file.h"
#include "fpm_crypt.h"
#include "support.h"

#define VAULT_DECRYPT_OK 0
#define VAULT_DECRYPT_FAIL -1

static void new_leaf_encrypt_password (xmlDocPtr doc, xmlNodePtr item, fpm_data *data);

static void encrypt_vault (xmlNodePtr node, xmlDocPtr doc, gchar *adata) {

    gchar *data;
    byte *tag;

    xmlBufferPtr nodeBuffer = xmlBufferCreate();
    gsize len = xmlNodeDump (nodeBuffer, doc, node, 0, 1);

    fpm_set_iv (crypto->new, crypto->iv);
    fpm_add_data (crypto->new, strlen (adata), (byte *)adata);
    data = fpm_encrypt_data_base64 (crypto->new, nodeBuffer->content, len);
    tag = g_malloc (crypto->cipher_info->digestsize);
    fpm_get_tag (crypto->new, crypto->cipher_info->digestsize, tag);

    xmlBufferFree (nodeBuffer);

    xmlNodePtr vault = xmlNewChild (doc->xmlRootNode, NULL, (xmlChar *)"Vault", (xmlChar *)data);

    gchar *ctag = g_base64_encode (tag, crypto->cipher_info->digestsize);
    xmlSetProp (vault, (xmlChar *)"tag", (xmlChar *)ctag);

    g_free (tag);
    g_free (data);

    xmlReplaceNode (node, vault);
}

static int decrypt_vault (xmlNodePtr node, gchar *adata, byte *tag_old) {

    xmlNodePtr vault;
    gchar *decrypted;
    byte *tag_new;

    tag_new = malloc (crypto->cipher_info->digestsize);

    fpm_add_data (crypto->old, strlen (adata), (byte *)adata);
    decrypted = fpm_decrypt_data_base64 (crypto->old, (char *)node->xmlChildrenNode->content);
    fpm_get_tag (crypto->old, crypto->cipher_info->digestsize, tag_new);

    /* Check if MAC is correct */
    if (memcmp (tag_old, tag_new, crypto->cipher_info->digestsize)) {
	g_free (tag_new);
	g_free (decrypted);
	return (VAULT_DECRYPT_FAIL);
    }

    xmlParseInNodeContext (node, decrypted, strlen (decrypted), 0, &vault);
    xmlReplaceNode (node, vault);

    g_free (tag_new);
    g_free (decrypted);

    return (VAULT_DECRYPT_OK);
}

static void passfile_update_key(void)
/* This routine goes through the entire password list and will decrypt the
 * passwords with an old key and encrypt it again with a new key.  This is
 * needed in two situations: First, if the user changes a password.  Secondly,
 * (and much more common) if the salt changes.  In practice, this routine gets
 * called whenever we save a file.
 */
{
    fpm_data *data;
    gchar plaintext[FPM_PASSWORD_LEN + 1] = {0};
    GList *list;
    guint ix;

    if (crypto->old->context != crypto->new->context) {
        list = g_list_first (glb_pass_list);
        while (list != NULL) {
            data = list->data;
            ix = strlen (data->password) / 2;

	    if (!state->legacy_cipher) {
		fpm_set_iv (crypto->old, data->iv);
	    }

            fpm_decrypt_field (crypto->old, plaintext, data->password, ix);

	    if (!state->legacy_cipher) {
		g_free (data->iv);
    		data->iv = fpm_get_new_iv ();
		fpm_set_iv (crypto->new, data->iv);
	    }

            fpm_encrypt_field (crypto->new, data->password, plaintext, FPM_PASSWORD_LEN);

	    if (!state->legacy_cipher) {
		g_free (data->tag);
		data->tag = g_malloc (crypto->cipher_info->digestsize);
		fpm_get_tag (crypto->new, crypto->cipher_info->digestsize, data->tag);
	    }

            list = g_list_next (list);
        }

        wipememory (plaintext, FPM_PASSWORD_LEN);
        memcpy (crypto->old->context, crypto->new->context , crypto->cipher_info->contextsize);
        memcpy (crypto->old->salt, crypto->new->salt, FPM_SALT_SIZE);

        crypto->old->decryption_prepared = FALSE;
    }
}

static void move_backup (gchar *file_name) {
    gchar file1[512];
    gchar file2[512];
    gint i;

    for (i = ini->number_backup_files; i > 0; i--) {
        g_snprintf (file2, 512, "%s.%02d", file_name, i);
        if (i > 1)
            g_snprintf (file1, 512, "%s.%02d", file_name, i - 1);
        else
            g_snprintf (file1, 512, "%s", file_name);

        rename (file1, file2);
    }
}

static void passfile_upd_attr (xmlNodePtr node, char *cond, char **data_ptr) {
    if (!strcmp ((char *)node->name, cond)) {
        g_free (*data_ptr);
        if (node->xmlChildrenNode != NULL)
            *data_ptr = g_strdup ((char *)node->xmlChildrenNode->content);
        else
            *data_ptr = g_strdup ("");
    }
}

static void new_leaf (xmlDocPtr doc, xmlNodePtr item, const gchar *name, gchar *text) {
    xmlChar *tmp;

    tmp = xmlEncodeEntitiesReentrant (doc, (xmlChar *)text);
    xmlNewChild (item, NULL, (xmlChar *)name, tmp);
    xmlFree (tmp);
}

static void new_leaf_encrypt (xmlDocPtr doc, xmlNodePtr item, const gchar *name, gchar *text) {
    gchar *cipher_text;

    cipher_text = fpm_encrypt_field_var (crypto->new, text);
    new_leaf (doc, item, name, cipher_text);
    g_free (cipher_text);
}

void fpm_file_save (gchar *file_name, gboolean convert) {
    xmlDocPtr doc;
    xmlNodePtr nodelist, item;
    fpm_data *data;
    fpm_launcher *launcher;
    FILE *file;
    gchar *tmp;
    GList *list;
    gint i;
    gchar *dia_str;
    gchar *vstring_cipher = "";
    gchar *vstring_plain = "";
    gchar *iv = "", *salt = "";

    if (ini->create_backup)
        move_backup(file_name);

    if (!convert)
        passfile_update_key();

    if (!state->legacy_cipher) {
	/* Generate new IV for vault encrypt */
	crypto->iv = fpm_get_new_iv();
        fpm_set_iv (crypto->new, crypto->iv);
        iv = g_base64_encode (crypto->iv, crypto->cipher_info->ivsize);
        salt = g_base64_encode (crypto->new->salt, FPM_SALT_SIZE);
    }

    doc = xmlNewDoc ((xmlChar *)"1.0");
    doc->xmlRootNode = xmlNewDocNode (doc, NULL, (xmlChar *)"FPM", NULL);
    xmlSetProp (doc->xmlRootNode, (xmlChar *)"full_version", (xmlChar *)FULL_VERSION);

    if (state->legacy_cipher)
        xmlSetProp (doc->xmlRootNode, (xmlChar *)"min_version", (xmlChar *)MIN_VERSION_AES256);
    else
        xmlSetProp (doc->xmlRootNode, (xmlChar *)"min_version", (xmlChar *)MIN_VERSION);

    item = xmlNewChild (doc->xmlRootNode, NULL, (xmlChar *)"KeyInfo", NULL);

    xmlSetProp (item, (xmlChar *)"cipher", (xmlChar *)crypto->cipher_info->name);

    if (state->legacy_cipher) {

        vstring_cipher = g_malloc0 (FPM_HASH_SIZE * 2 + 1);
        vstring_plain = g_malloc (FPM_HASH_SIZE + 1);
        fpm_sha256_fpm_data (vstring_plain);
        fpm_encrypt_field (crypto->new, vstring_cipher, vstring_plain, FPM_HASH_SIZE);

        xmlSetProp (item, (xmlChar *)"salt", (xmlChar *)crypto->new->salt);
        xmlSetProp (item, (xmlChar *)"vstring", (xmlChar *)vstring_cipher);

        g_free (vstring_plain);
        g_free (vstring_cipher);

    } else {

        salt = g_base64_encode (crypto->new->salt, FPM_SALT_SIZE);
        xmlSetProp (item, (xmlChar *)"salt", (xmlChar *)salt);
        xmlSetProp (item, (xmlChar *)"iv", (xmlChar *)iv);
        xmlSetProp (item, (xmlChar *)"kdf", (xmlChar *)"PBKDF2");
        xmlSetProp (item, (xmlChar *)"kdf_iterations", (xmlChar *)g_strdup_printf ("%i", crypto->kdf_iterations));
    }

    xmlNodePtr vault;
    if (state->legacy_cipher)
        vault = doc->xmlRootNode;
    else
        vault = xmlNewChild (doc->xmlRootNode, NULL, (xmlChar *)"Vault", NULL);

    nodelist = xmlNewChild (vault, NULL, (xmlChar *)"LauncherList", NULL);
    list = g_list_first (glb_launcher_list);

    while (list != NULL) {
        launcher = list->data;
        item = xmlNewChild (nodelist, NULL, (xmlChar *)"LauncherItem", NULL);
        if (state->legacy_cipher) {
            new_leaf_encrypt (doc, item, "title", launcher->title);
            new_leaf_encrypt (doc, item, "cmdline", launcher->cmdline);
            tmp = g_strdup_printf ("%d", launcher->copy_user);
            new_leaf_encrypt (doc, item, "copy_user", tmp);
            g_free (tmp);
            tmp = g_strdup_printf ("%d", launcher->copy_password);
            new_leaf_encrypt (doc, item, "copy_password", tmp);
        } else {
            new_leaf (doc, item, "title", launcher->title);
            new_leaf (doc, item, "cmdline", launcher->cmdline);
            tmp = g_strdup_printf ("%d", launcher->copy_user);
            new_leaf (doc, item, "copy_user", tmp);
            g_free (tmp);
            tmp = g_strdup_printf ("%d", launcher->copy_password);
            new_leaf (doc, item, "copy_password", tmp);
        }
        g_free (tmp);
        list = g_list_next (list);
    }

    nodelist = xmlNewChild (vault, NULL, (xmlChar *)"PasswordList", NULL);
    list = g_list_first (glb_pass_list);
    i = 0;
    while (list != NULL) {
        data = list->data;
        item = xmlNewChild (nodelist, NULL, (xmlChar *)"PasswordItem", NULL);

        if (state->legacy_cipher) {

            new_leaf_encrypt (doc, item, "title", data->title);
            new_leaf_encrypt (doc, item, "user", data->user);
            new_leaf_encrypt (doc, item, "url", data->arg);

            new_leaf (doc, item, "password", data->password);

            new_leaf_encrypt (doc, item, "notes", data->notes);
            new_leaf_encrypt (doc, item, "category", data->category);
            new_leaf_encrypt (doc, item, "launcher", data->launcher);

        } else {

            new_leaf (doc, item, "title", data->title);
            new_leaf (doc, item, "user", data->user);
            new_leaf (doc, item, "url", data->arg);

            if (convert)
                new_leaf_encrypt_password (doc, item, data);
            else
                new_leaf (doc, item, "password", data->password);

	    new_leaf (doc, item, "iv", g_base64_encode (data->iv, crypto->cipher_info->ivsize));
	    new_leaf (doc, item, "tag", g_base64_encode (data->tag, crypto->cipher_info->digestsize));
            new_leaf (doc, item, "notes", data->notes);
            new_leaf (doc, item, "category", data->category);
            new_leaf (doc, item, "launcher", data->launcher);
        }

        if (data->default_list) xmlNewChild (item, NULL, (xmlChar *)"default", NULL);

        list = g_list_next (list);
        i++;
    }

    if (!state->legacy_cipher) {
        gchar *adata = g_strdup_printf ("%s%s%s%i", crypto->cipher_info->name, salt, iv, crypto->kdf_iterations);
        encrypt_vault (vault, doc, adata);
	g_free (adata);
    }

    file = fopen (file_name, "w");
    xmlDocFormatDump (file, doc, 1);
    fclose (file);

    dia_str = g_strdup_printf (_ ("Saved %d password(s)."), i);
    fpm_statusbar_push (dia_str);

    xmlFreeDoc (doc);
    fpm_dirty (FALSE);
}

void
passfile_save (gchar *file_name) {
    fpm_file_save (file_name, FALSE);
    unlock_fpm_file();
    lock_fpm_file(file_name);
}

void fpm_file_export (gchar *file_name, gint export_launchers, gchar *export_category) {
    xmlDocPtr doc;
    xmlNodePtr nodelist, item;
    fpm_data *data;
    fpm_launcher *launcher;
    FILE *file;
    gchar *tmp;
    GList *list;
    gint i;
    gchar plaintext[FPM_PASSWORD_LEN + 1] = {0};
    gchar *dia_str;

    doc = xmlNewDoc ((xmlChar *)"1.0");
    doc->xmlRootNode = xmlNewDocNode (doc, NULL, (xmlChar *)"FPM", NULL);
    xmlSetProp (doc->xmlRootNode, (xmlChar *)"full_version", (xmlChar *)FULL_VERSION);
    xmlSetProp (doc->xmlRootNode, (xmlChar *)"min_version", (xmlChar *)MIN_VERSION);
    xmlSetProp (doc->xmlRootNode, (xmlChar *)"display_version", (xmlChar *)DISPLAY_VERSION);
    item = xmlNewChild (doc->xmlRootNode, NULL, (xmlChar *)"KeyInfo", NULL);
    xmlSetProp (item, (xmlChar *)"cipher", (xmlChar *)"none");

    if (export_launchers) {

        nodelist = xmlNewChild (doc->xmlRootNode, NULL, (xmlChar *)"LauncherList", NULL);
        list = g_list_first (glb_launcher_list);

        while (list != NULL) {
            launcher = list->data;
            if ((export_launchers == 2) || ((export_launchers == 1) && fpm_is_launcher_in_category (launcher, export_category))) {
                item = xmlNewChild (nodelist, NULL, (xmlChar *)"LauncherItem", NULL);
                new_leaf (doc, item, "title", launcher->title);
                new_leaf (doc, item, "cmdline", launcher->cmdline);
                tmp = g_strdup_printf ("%d", launcher->copy_user);
                new_leaf (doc, item, "copy_user", tmp);
                g_free (tmp);
                tmp = g_strdup_printf ("%d", launcher->copy_password);
                new_leaf (doc, item, "copy_password", tmp);
                g_free (tmp);
            }

            list = g_list_next (list);
        }

    }
    nodelist = xmlNewChild (doc->xmlRootNode, NULL, (xmlChar *)"PasswordList", NULL);
    list = g_list_first (glb_pass_list);
    i = 0;

    while (list != NULL) {
        data = list->data;

        if (!strcmp (export_category, data->category) || !strcmp (export_category, FPM_ALL_CAT_MSG)) {

            item = xmlNewChild (nodelist, NULL, (xmlChar *)"PasswordItem", NULL);
            new_leaf (doc, item, "title", data->title);
            new_leaf (doc, item, "user", data->user);
            new_leaf (doc, item, "url", data->arg);

	    if (!state->legacy_cipher) {
		fpm_set_iv(crypto->old, data->iv);
	    }

            fpm_decrypt_field (crypto->old, plaintext, data->password, FPM_PASSWORD_LEN);

            new_leaf (doc, item, "password", plaintext);
            new_leaf (doc, item, "notes", data->notes);
            new_leaf (doc, item, "category", data->category);
            new_leaf (doc, item, "launcher", data->launcher);

            if (data->default_list) xmlNewChild (item, NULL, (xmlChar *)"default", NULL);
            i++;
        }
        list = g_list_next (list);
    }

    /* Zero out plain text */
    wipememory (plaintext, FPM_PASSWORD_LEN);

    file = fopen (file_name, "w");
    xmlDocDump (file, doc);
    fclose (file);

    dia_str = g_strdup_printf (_ ("Exported clear XML passwords to %s."), file_name);
    fpm_statusbar_push (dia_str);
    g_free (dia_str);
}

gint fpm_file_load (gchar *file_name, gchar *password) {

    xmlDocPtr doc;
    xmlNodePtr list, item, attr;
    fpm_data *data;
    fpm_launcher *launcher;
    gint i;
    gchar *cipher_name;
    gchar *file_version;
    gchar *vstring = "";

    /* Start from scratch */
    if (glb_pass_list != NULL) fpm_clear_list ();

    LIBXML_TEST_VERSION
    xmlKeepBlanksDefault (0);
    doc = xmlParseFile (file_name);
    if (doc == NULL) {
        return (FILE_NOT_FPM);
    }

    /* Check if document is one of ours */
    if (xmlStrcmp (doc->xmlRootNode->name, (xmlChar *)"FPM"))
	return (FILE_NOT_FPM);

    file_version = (char *)xmlGetProp (doc->xmlRootNode, (xmlChar *)"min_version");
    if (strcmp (file_version, FULL_VERSION) > 0) {
	return (FILE_FUTURE);
    }
    xmlFree (file_version);

    file_version = (char *)xmlGetProp (doc->xmlRootNode, (xmlChar *)"full_version");

    list = doc->xmlRootNode->xmlChildrenNode;

    cipher_name = (char *)xmlGetProp (list, (xmlChar *)"cipher");
    if (cipher_name == NULL) {
	return (FILE_OLD);
    }

    if (fpm_get_cipher_algo(cipher_name) == CIPHER_UNKNOWN) {
	return (FILE_UNKNOWN_CIPHER);
    }

    fpm_cipher_init (cipher_name);

    if (!strcmp (cipher_name, "AES-256")) {
	/* Legacy mode enabled */
	state->legacy_cipher = TRUE;

        crypto->old->salt = (byte *)xmlGetProp (list, (xmlChar *)"salt");
        vstring = (char *)xmlGetProp (list, (xmlChar *)"vstring");

        crypto->new->salt = (guint8 *) get_new_salt (FPM_SALT_SIZE);

    } else {
        gsize out_len;

        crypto->old->salt = g_base64_decode ((gchar *) xmlGetProp (list, (xmlChar *)"salt"), &out_len);
        crypto->new->salt = fpm_get_new_salt (FPM_SALT_SIZE);
    }

    gchar *kdf = (char *)xmlGetProp (list, (xmlChar *)"kdf");
    xmlChar *iterations = xmlGetProp (list, (xmlChar *)"kdf_iterations");
    gchar *iv = (char *)xmlGetProp (list, (xmlChar *)"iv");

    /* Set KDF for legacy FPM2 data file */
    if (kdf == NULL)
        kdf = "PBKDF2";

    if (iterations == NULL)
        crypto->kdf_iterations = PBKDF2_ITERATIONS_DEFAULT_OLD;
    else {
        crypto->kdf_iterations = atoi ((char *)iterations);
        xmlFree (iterations);
    }

    fpm_crypt_init (password);

    list = list->next;

    if (!strcmp ((char *)list->name, "Vault")) {
        gchar *tag = (char *)xmlGetProp (list, (xmlChar *)"tag");
        gsize out_len;

        byte *tagc = g_base64_decode (tag, &out_len);
        byte *ivb = g_base64_decode (iv, &out_len);

        fpm_set_iv (crypto->old, ivb);

        gchar *adata = g_strdup_printf ("%s%s%s%i", crypto->cipher_info->name, g_base64_encode (crypto->old->salt, FPM_SALT_SIZE), iv, crypto->kdf_iterations);

        int result = decrypt_vault (list, adata, tagc);

	xmlFree (tag);
	g_free (tagc);
	g_free (ivb);

	if (result == VAULT_DECRYPT_FAIL) {
	    return (FILE_DECRYPT_FAIL);
	}

        list = doc->xmlRootNode->xmlChildrenNode;
        list = list->next;
        list = list->xmlChildrenNode;
    }

    if (list == NULL || (strcmp ((char *)list->name, "PasswordList") && strcmp ((char *)list->name, "LauncherList"))) {
        return (FILE_INVALID);
    }

    if (!strcmp ((char *)list->name, "LauncherList")) {
        glb_launcher_list = NULL;
        item = list->xmlChildrenNode;
        while (item != NULL) {
            launcher = g_malloc0 (sizeof (fpm_launcher));
            launcher->title = g_strdup ("");
            launcher->cmdline = g_strdup ("");
            launcher->c_user = g_strdup ("");
            launcher->c_pass = g_strdup ("");
            launcher->copy_user = 0;
            launcher->copy_password = 0;
            attr = item->xmlChildrenNode;
            while (attr != NULL) {
                if (!strcmp ((char *)attr->name, "title") && attr->xmlChildrenNode && attr->xmlChildrenNode->content) {
                    g_free (launcher->title);
                    launcher->title = g_strdup ((char *)attr->xmlChildrenNode->content);
                }
                if (!strcmp ((char *)attr->name, "cmdline") && attr->xmlChildrenNode && attr->xmlChildrenNode->content) {
                    g_free (launcher->cmdline);
                    launcher->cmdline = g_strdup ((char *)attr->xmlChildrenNode->content);
                }
                if (cipher_algo != AES256) {
                    if (!strcmp ((char *)attr->name, "copy_user")) {
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "1")) launcher->copy_user = 1;
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "2")) launcher->copy_user = 2;
                    }
                    if (!strcmp ((char *)attr->name, "copy_password")) {
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "1")) launcher->copy_password = 1;
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "2")) launcher->copy_password = 2;
                    }
                } else {
                    if (!strcmp ((char *)attr->name, "copy_user") && attr->xmlChildrenNode && attr->xmlChildrenNode->content) {
                        g_free (launcher->c_user);
                        launcher->c_user = g_strdup ((char *)attr->xmlChildrenNode->content);
                    }
                    if (!strcmp ((char *)attr->name, "copy_password") && attr->xmlChildrenNode && attr->xmlChildrenNode->content) {
                        g_free (launcher->c_pass);
                        launcher->c_pass = g_strdup ((char *)attr->xmlChildrenNode->content);
                    }
                }
                attr = attr->next;
            }
            glb_launcher_list = g_list_append (glb_launcher_list, launcher);

            item = item->next;
        }
        fpm_create_launcher_string_list();

        /* Incurement top-level list from launcher list to password list. */
        list = list->next;
    } else {
        fpm_init_launchers();
    }

    if (list == NULL || strcmp ((char *)list->name, "PasswordList")) {
        return (FILE_INVALID);
    }

    i = 0;

    item = list->xmlChildrenNode;
    while (item != NULL) {

        /* Start with blank data record */
        data = g_malloc0 (sizeof (fpm_data));
        data->title = g_strdup ("");
        data->arg = g_strdup ("");
        data->user = g_strdup ("");
        data->notes = g_strdup ("");
        data->category = g_strdup ("");
        data->launcher = g_strdup ("");
        data->default_list = 0;

        /* Update data record with each type of attribute */
        attr = item->xmlChildrenNode;
        while (attr != NULL) {
            passfile_upd_attr (attr, "title", &data->title);
            passfile_upd_attr (attr, "url", &data->arg);
            passfile_upd_attr (attr, "user", &data->user);
            passfile_upd_attr (attr, "notes", &data->notes);
            passfile_upd_attr (attr, "category", &data->category);
            passfile_upd_attr (attr, "launcher", &data->launcher);
            if (!strcmp ((char *)attr->name, "default")) {
                data->default_list = 1;
            }

            if (!strcmp ((char *)attr->name, "password"))
                strncpy (data->password, (char *)attr->xmlChildrenNode->content, FPM_PASSWORD_LEN * 2);

	    if (!state->legacy_cipher) {
    		gsize out_len;
    		if (!strcmp ((char *)attr->name, "iv"))
		    data->iv = g_base64_decode  ((char *)attr->xmlChildrenNode->content, &out_len);
    		if (!strcmp ((char *)attr->name, "tag"))
		    data->tag = g_base64_decode ((char *)attr->xmlChildrenNode->content, &out_len);
	    }

            attr = attr->next;
        }

        /* Insert item into GList */
        glb_pass_list = g_list_append (glb_pass_list, data);

        item = item->next;
        i++;
    }

    xmlFreeDoc (doc);
    free (file_version);

    /* Check if legacy cipher decrypt ok */
    if (state->legacy_cipher) {
        gchar *vhash = g_malloc0 (FPM_HASH_SIZE + 1);
        gchar *vstring_plain = g_malloc0 (FPM_HASH_SIZE + 1);

        fpm_decrypt_launchers();
        fpm_decrypt_all();

        fpm_sha256_fpm_data (vhash);

        fpm_decrypt_field(crypto->old, vstring_plain, vstring, FPM_HASH_SIZE);

        if (strcmp (vstring_plain, vhash)) {
	    g_free(vstring_plain);
    	    g_free(vhash);
    	    return FILE_DECRYPT_FAIL;
	}
        g_free(vstring_plain);
        g_free(vhash);
    }

    fpm_dirty (FALSE);

    return (FILE_OK);
}

static void new_leaf_encrypt_password (xmlDocPtr doc, xmlNodePtr item, fpm_data *data) {

    gchar cipher_text[FPM_PASSWORD_LEN * 2 + 1] = {0};
    gchar plaintext[FPM_PASSWORD_LEN + 1] = {0};

    memcpy (plaintext, data->password, FPM_PASSWORD_LEN - 1);

    if (!state->legacy_cipher) {
	data->iv = fpm_get_new_iv ();
	data->tag = g_malloc (crypto->cipher_info->digestsize);
	fpm_set_iv (crypto->new, data->iv);
    }

    fpm_encrypt_field (crypto->new, cipher_text, plaintext, FPM_PASSWORD_LEN);
    new_leaf (doc, item, "password", cipher_text);

    if (!state->legacy_cipher) {
	fpm_get_tag (crypto->new, crypto->cipher_info->digestsize, data->tag);
    }

    wipememory (plaintext, FPM_PASSWORD_LEN);
}

void fpm_file_convert (gchar *file_name, gchar *password, gchar *cipher) {
    gchar plaintext[FPM_PASSWORD_LEN + 1] = {0};
    fpm_data *data;
    GList *list;
    guint ix;

    list = g_list_first (glb_pass_list);
    while (list != NULL) {
        data = list->data;
        ix = strlen (data->password) / 2;

	if (!state->legacy_cipher) {
	    fpm_set_iv(crypto->old, data->iv);
	}

        fpm_decrypt_field (crypto->old, plaintext, data->password, ix);
        memcpy (data->password, plaintext, strlen (plaintext) + 1);

        list = g_list_next (list);
    }

    wipememory (plaintext, FPM_PASSWORD_LEN);

    g_free (crypto->old->salt);
    g_free (crypto->new->salt);

    g_free (crypto->old->context);
    g_free (crypto->new->context);

    g_free (crypto->old);
    g_free (crypto->new);

    g_free (crypto->iv);

    state->legacy_cipher = FALSE;
    fpm_cipher_init (cipher);

    crypto->old->salt = fpm_get_new_salt (FPM_SALT_SIZE);
    crypto->new->salt = g_malloc (FPM_SALT_SIZE);
    memcpy (crypto->new->salt, crypto->old->salt, FPM_SALT_SIZE);

    fpm_crypt_init (password);

    fpm_file_save (file_name, TRUE);
}


gint
fpm_file_import (gchar *file_name, gint import_launchers, gchar *import_category, gint import_entries, gchar **message) {
    xmlDocPtr doc;
    xmlNodePtr list, item, attr;
    fpm_data *data;
    fpm_launcher *launcher;
    gint i;
    gchar plaintext[FPM_PASSWORD_LEN + 1] = {0};

    LIBXML_TEST_VERSION
    xmlKeepBlanksDefault (0);
    doc = xmlParseFile (file_name);
    if (doc == NULL) {
        *message = g_strdup (_ ("File is not XML?"));
        return (-1);
    }

    /* Check if document is one of ours */
    if (xmlStrcmp (doc->xmlRootNode->name, (xmlChar *)"FPM")) {
        *message = g_strdup (_ ("File is not valid FPM2 password file."));
        return (-1);
    }

    list = doc->xmlRootNode->xmlChildrenNode;

    list = list->next;

    if (list == NULL || (strcmp ((char *)list->name, "PasswordList") && strcmp ((char *)list->name, "LauncherList"))) {
        *message = g_strdup (_ ("Invalid password file."));
        return (-1);
    }

    if (!strcmp ((char *)list->name, "LauncherList")) {
        if (import_launchers != 0) {
            if (import_launchers == 2)
                fpm_launcher_remove_all();
            item = list->xmlChildrenNode;
            while (item != NULL) {
                launcher = g_malloc0 (sizeof (fpm_launcher));
                launcher->title = g_strdup ("");
                launcher->cmdline = g_strdup ("");
                launcher->copy_user = 0;
                launcher->copy_password = 0;
                attr = item->xmlChildrenNode;
                while (attr != NULL) {
                    if (!strcmp ((char *)attr->name, "title") && attr->xmlChildrenNode && attr->xmlChildrenNode->content) {
                        g_free (launcher->title);
                        launcher->title = g_strdup ((char *)attr->xmlChildrenNode->content);
                    }
                    if (!strcmp ((char *)attr->name, "cmdline") && attr->xmlChildrenNode && attr->xmlChildrenNode->content) {
                        g_free (launcher->cmdline);
                        launcher->cmdline = g_strdup ((char *)attr->xmlChildrenNode->content);
                    }
                    if (!strcmp ((char *)attr->name, "copy_user")) {
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "1")) launcher->copy_user = 1;
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "2")) launcher->copy_user = 2;
                    }
                    if (!strcmp ((char *)attr->name, "copy_password")) {
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "1")) launcher->copy_password = 1;
                        if (!strcmp ((char *)attr->xmlChildrenNode->content, "2")) launcher->copy_password = 2;
                    }
                    attr = attr->next;
                }

                if ((import_launchers == 2) || ((import_launchers == 1) && !fpm_launcher_search (launcher->title)))
                    glb_launcher_list = g_list_append (glb_launcher_list, launcher);

                item = item->next;
            }
            fpm_create_launcher_string_list();
        }
        /* Incurement top-level list from launcher list to password list. */
        list = list->next;

    }

    if (list == NULL || strcmp ((char *)list->name, "PasswordList")) {
        *message = g_strdup (_ ("Invalid password file."));
        return (-1);
    }

    i = 0;

    item = list->xmlChildrenNode;
    while (item != NULL) {

        /* Start with blank data record */
        data = g_malloc0 (sizeof (fpm_data));
        data->title = g_strdup ("");
        data->arg = g_strdup ("");
        data->user = g_strdup ("");
        data->notes = g_strdup ("");
        if (strcmp (import_category, FPM_NONE_CAT_MSG))
            data->category = g_strdup (import_category);
        else
            data->category = g_strdup ("");
        data->launcher = g_strdup ("");
        data->default_list = 0;

        /* Update data record with each type of attribute */
        attr = item->xmlChildrenNode;
        while (attr != NULL) {
            passfile_upd_attr (attr, "title", &data->title);
            passfile_upd_attr (attr, "url", &data->arg);
            passfile_upd_attr (attr, "user", &data->user);
            passfile_upd_attr (attr, "notes", &data->notes);
            if (!strcmp (import_category, ""))
                passfile_upd_attr (attr, "category", &data->category);
            passfile_upd_attr (attr, "launcher", &data->launcher);

            if (!strcmp ((char *)attr->name, "default")) {
                data->default_list = 1;
            }

            if (!strcmp ((char *)attr->name, "password")) {
                gchar *xmlplain;

                xmlplain = (gchar *)xmlNodeListGetString (doc, attr->xmlChildrenNode, 1);
                if (xmlplain != NULL) {
                    g_strlcpy (plaintext, xmlplain, sizeof (plaintext));
                } else {
                    plaintext[0] = '\0';
                }

		if (!state->legacy_cipher) {
    		    data->iv = fpm_get_new_iv ();
		    data->tag = g_malloc (crypto->cipher_info->digestsize);
		    fpm_set_iv (crypto->old, data->iv);
		}

		fpm_encrypt_field(crypto->old, data->password, plaintext, FPM_PASSWORD_LEN);

		if (!state->legacy_cipher) {
		    fpm_get_tag (crypto->old, crypto->cipher_info->digestsize, data->tag);
		}

                xmlFree (xmlplain);
            }

            attr = attr->next;
        }

	if (import_entries > 0) {
	    GList *glist = g_list_first (glb_pass_list);
	    fpm_data *fdata;

	    while (glist != NULL) {
		fdata = glist->data;

		if ((!g_utf8_collate (data->title, fdata->title) && (import_entries == 1)) || 
		     (!g_utf8_collate (data->category, fdata->category) && !g_utf8_collate (data->title, fdata->title) && (import_entries == 2))) {

		    glb_pass_list = g_list_remove (glb_pass_list, fdata);

		    glist = g_list_first (glb_pass_list);
		    continue;
		}

		glist = g_list_next (glist);
	    }
	}

        /* Insert item into GList */
        glb_pass_list = g_list_append (glb_pass_list, data);

        item = item->next;
        i++;
    }
    xmlFreeDoc (doc);

    fpm_dirty (TRUE);

    *message = g_strdup_printf (_ ("Imported %d password(s)."), i);

    return (0);
}
