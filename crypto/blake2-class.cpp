// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/blake2.h"
#include "crypto/blake2-class.h"

#include "crypto/common.h"



#include <string.h>


////// BLAKE2-224

//int blake2b_init( blake2b_state *S, size_t outlen );
//int blake2b_update( blake2b_state *S, const void *in, size_t inlen );
//int blake2b_final( blake2b_state *S, void *out, size_t outlen );

CBLAKE2224::CBLAKE2224() : bytes(0)
{
    blake2b_init( &s, OUTPUT_SIZE)
   // ripemd160::Initialize(s);
}

CBLAKE2224& CBLAKE2224::Write(const unsigned char* data, size_t len)
{
   //call out to containing function
   bytes += len; //running count of size of data
   blake2b_update( &s , (const void *) data, len);
   return *this;
}

void CBLAKE2224::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteLE64(sizedesc, bytes << 3);  //bit size...
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    blake2b_final( &s, (void *) hash, OUTPUT_SIZE)
    //WriteLE32(hash, s[0]);
    //WriteLE32(hash + 4, s[1]);
    //WriteLE32(hash + 8, s[2]);
    //WriteLE32(hash + 12, s[3]);
    //WriteLE32(hash + 16, s[4]);
}

CBLAKE2224& CBLAKE2224::Reset()
{
    bytes = 0;
    // 
    blake2b_init(&s, OUTPUT_SIZE);
    return *this;
}
