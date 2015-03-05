/*
 * Copyright (c) 2011 Hunter Morris <hunter.morris@smarkets.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "erl_nif.h"
#include "erl_blf.h"

#define BCRYPT_MAXSALT 16	/* Precomputation is just so nice */
#define BCRYPT_SALTSPACE	(7 + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1)
#define BCRYPT_HASHSPACE	61

int bcrypt(const char *, const char *, char *, size_t);
void encode_salt(char *, size_t, uint8_t *, uint16_t, int);

static ERL_NIF_TERM erl_encode_salt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary csalt, bin;
    unsigned long log_rounds;

    if (!enif_inspect_binary(env, argv[0], &csalt) || 16 != csalt.size) {
        return enif_make_badarg(env);
    }

    if (!enif_get_ulong(env, argv[1], &log_rounds)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(64, &bin)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    encode_salt((char *)bin.data, bin.size, (uint8_t*)csalt.data, csalt.size,
            log_rounds);
    enif_release_binary(&csalt);

    return enif_make_string(env, (char *)bin.data, ERL_NIF_LATIN1);
}

static ERL_NIF_TERM hashpw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char pw[1024];
    char salt[1024];
    char encrypted[BCRYPT_HASHSPACE];

    (void)memset(&pw, '\0', sizeof(pw));
    (void)memset(&salt, '\0', sizeof(salt));

    if (enif_get_string(env, argv[0], pw, sizeof(pw), ERL_NIF_LATIN1) < 1)
        return enif_make_badarg(env);

    if (enif_get_string(env, argv[1], salt, sizeof(salt), ERL_NIF_LATIN1) < 1)
        return enif_make_badarg(env);

    if (bcrypt(pw, salt, encrypted, sizeof(encrypted)) ||
            0 == strcmp(encrypted, ":")) {
        return enif_make_badarg(env);
    }

    return enif_make_string(env, encrypted, ERL_NIF_LATIN1);
}

static ErlNifFunc bcrypt_nif_funcs[] =
{
    {"encode_salt", 2, erl_encode_salt},
    {"hashpw", 2, hashpw}
};

ERL_NIF_INIT(bcrypt, bcrypt_nif_funcs, NULL, NULL, NULL, NULL)
