// Copyright (c) 2017 GuangCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_BLAKE2_CLASS_H
#define BITCOIN_CRYPTO_BLAKE2_CLASS_H

#include <stdint.h>
#include <stdlib.h>
#include "blake2.h"


//int blake2b_init( blake2b_state *S, size_t outlen );
//  int blake2b_init_key( blake2b_state *S, size_t outlen, const void *key, size_t keylen );
//  int blake2b_init_param( blake2b_state *S, const blake2b_param *P );
//  int blake2b_update( blake2b_state *S, const void *in, size_t inlen );
//  int blake2b_final( blake2b_state *S, void *out, size_t outlen );

/** A hasher class for Blake 2 (224). */
class CBLAKE2224
{
private:
    blake2b_state s;
    //unsigned char buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 28;

    CBLAKE2224();
    CBLAKE2224& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CBLAKE2224& Reset();
};

#endif // BITCOIN_CRYPTO_RIPEMD160_H
