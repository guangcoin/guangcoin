// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pubkey.h"


namespace
{
/* Global secp256k1_context object used for verification. */
//secp256k1_context* secp256k1_context_verify = NULL;

/* Global picnic state? */

}


bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;

    //ingest serialised pubkey into real key?
    //if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size())) {
    //    return false;
    //}
    if (vchSig.size() == 0) {
        return false;
    }
//TODOGUANG
    //int picnic_verify(picnic_publickey_t* pk, const uint8_t* message, size_t message_len,
    //              const uint8_t* signature, size_t signature_len);	

   //array is +1 bigger than max sig size?
    picnic_publickey_t pk;
    memcpy(pk.pubInput, &keystore[0], 32);
    memcpy(pk.cipherText, &keystore[32], 32);
    pk.params = LowMC_256_256_10_38_UR; 
    uint8_t sigtmp[195459] = vchSig to array
    int ret = picnic_verify(&pk, (cont uint8_t *) hash.begin(), 32, sigtmp, 195458) ;
    memset(pk, 0x00, sizeof(picnic_publickey_t));
    return ret;
}

//no such thing as a compact PICNIC signature
bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    return false;
}

bool CPubKey::IsFullyValid() const {
    if (!IsValid())
        return false;
    secp256k1_pubkey pubkey;
    //attempt to reparse seralised key int picnic_read_public_key(picnic_publickey_t* key, const uint8_t* buf, size_t buflen);
    return secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size());
}

bool CPubKey::Decompress() {
    if (!IsValid())
        return false;
    return false;
}

// BIP32 STUFF [TODOGUANG - is child key derivation possible in this sense from PICNIC keys?]
bool CPubKey::Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    assert((nChild >> 31) == 0);
    assert(begin() + 33 == end());
    unsigned char out[64];
    BIP32Hash(cc, nChild, *begin(), begin()+1, out);
    memcpy(ccChild.begin(), out+32, 32);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_verify, &pubkey, out)) {
        return false;
    }
    unsigned char pub[33];
    size_t publen = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen, &pubkey, SECP256K1_EC_COMPRESSED);
    pubkeyChild.Set(pub, pub + publen);
    return true;
}

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, chaincode.begin(), 32);
    assert(pubkey.size() == 33);
    memcpy(code+41, pubkey.begin(), 33);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    pubkey.Set(code+41, code+BIP32_EXTKEY_SIZE);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return pubkey.Derive(out.pubkey, out.chaincode, _nChild, chaincode);
}

/* static */ bool CPubKey::CheckLowS(const std::vector<unsigned char>& vchSig) {
	return true; //fudge - but this distinction doesn't exist for PICNIC keys

}

/* static */ int ECCVerifyHandle::refcount = 0;

ECCVerifyHandle::ECCVerifyHandle()
{
    if (refcount == 0) {
        assert(secp256k1_context_verify == NULL);
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        assert(secp256k1_context_verify != NULL);
    }
    refcount++;
}

ECCVerifyHandle::~ECCVerifyHandle()
{
    refcount--;
    if (refcount == 0) {
        assert(secp256k1_context_verify != NULL);
        secp256k1_context_destroy(secp256k1_context_verify);
        secp256k1_context_verify = NULL;
    }
}
