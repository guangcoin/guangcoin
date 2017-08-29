// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include "hash.h"
#include "serialize.h"
#include "uint256.h"

#include <stdexcept>
#include <vector>

/**
 * secp256k1:
 * const unsigned int PRIVATE_KEY_SIZE = 279;
 * const unsigned int PUBLIC_KEY_SIZE  = 65;
 * const unsigned int SIGNATURE_SIZE   = 72;
 *
 * see www.keylength.com
 * script supports up to 75 for single byte push
 */

/* PICNIC

#define PICNIC_MAX_PUBLICKEY_SIZE 64            // Largest public key size, in bytes //
#define PICNIC_MAX_PRIVATEKEY_SIZE 64           // Largest private key size, in bytes //
#define PICNIC_MAX_SIGNATURE_SIZE  263786       // Largest signature size, in bytes //
*/


const unsigned int BIP32_EXTKEY_SIZE = 74;

/** A reference to a CKey: the Hash224 of its serialized public key */
class CKeyID : public uint224
{
public:
    CKeyID() : uint224() {}
    CKeyID(const uint224& in) : uint224(in) {}
};

typedef uint256 ChainCode;

/** An encapsulated public key. */
class CPubKey
{
private:

    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
	// CONVENIENTLY, this is the right size for a default PICNIC key too!
     */
    unsigned char vch[65];

    //! Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader)
    {
        if (chHeader == 2 || chHeader == 3)
            return 33;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return 65;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate()
    {
        vch[0] = 0xFF;
    }

public:
    //! Construct an invalid public key.
    CPubKey()
    {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    CPubKey(const std::vector<unsigned char>& _vch)
    {
        Set(_vch.begin(), _vch.end());
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey& a, const CPubKey& b)
    {
        return !(a == b);
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char*)vch, len);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned int len = ::ReadCompactSize(s);
        if (len <= 65) {
            s.read((char*)vch, len);
        } else {
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization) 
    // TODOGUANG - change out our RIPEMD160 hash for something actually QC resistant
    // Probably want Blake2b (224) hashes
    CKeyID GetID() const
    {
        return CKeyID(Hash224(vch, vch + size()));
    }

    //! Get the 256-bit hash of this public key.
    // TODOGUANG - this is fine, SHA256 is QC-secure
    uint256 GetHash() const
    {
        return Hash(vch, vch + size());
    }

    /*
     * Check syntactic correctness.
     *
     * Note that this is consensus critical as CheckSig() calls it!
     */
    bool IsValid() const
    {
        return size() > 0;
    }

    //! fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    //! Check whether this is a compressed public key.
    // TODOGUANG - no such thing as a compressed PICNIC key
    bool IsCompressed() const
    {
	return false;
        //return size() == 33;
    }

    /**
     * Verify a PICNIC signature (~72 bytes). TODOGUANG
     * If this public key is not fully valid, the return value will be false.
     */
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;

    /**
     * Check whether a signature is normalized (lower-S).
	IRRELEVANT TODOGUANG REMOVE
     */
    //static bool CheckLowS(const std::vector<unsigned char>& vchSig);

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint256& hash, const std::vector<unsigned char>& vchSig);

    //! Turn this public key into an uncompressed public key.
   // possibly irrelevant to PICNIG TODOGUANG
    //bool Decompress();

    //! Derive BIP32 child pubkey.
	// we might not support BIP32 keys via PICNIC TODOGUANG
    bool Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;
};

struct CExtPubKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return a.nDepth == b.nDepth &&
            memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], sizeof(vchFingerprint)) == 0 &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.pubkey == b.pubkey;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    bool Derive(CExtPubKey& out, unsigned int nChild) const;

    void Serialize(CSizeComputer& s) const
    {
        // Optimized implementation for ::GetSerializeSize that avoids copying.
        s.seek(BIP32_EXTKEY_SIZE + 1); // add one byte for the size (compact int)
    }
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = BIP32_EXTKEY_SIZE;
        ::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        Encode(code);
        s.write((const char *)&code[0], len);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned int len = ::ReadCompactSize(s);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if (len != BIP32_EXTKEY_SIZE)
            throw std::runtime_error("Invalid extended key size\n");
        s.read((char *)&code[0], len);
        Decode(code);
    }
};

/** Users of this module must hold an ECCVerifyHandle. The constructor and
 *  destructor of these are not allowed to run in parallel, though. */
class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};

#endif // BITCOIN_PUBKEY_H
