package key

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/thanhn-inc/debugtool/common"
	"math/big"
)

// BLSKeyGen take an input seed and return BLS Key
func BLSKeyGen(seed []byte) (*big.Int, *bn256.G2) {
	sk := BLSSKGen(seed)
	return sk, BLSPKGen(sk)
}

// BLSSKGen take a seed and return BLS secret key
func BLSSKGen(seed []byte) *big.Int {
	sk := big.NewInt(0)
	sk.SetBytes(common.HashB(seed))
	for {
		if sk.Cmp(bn256.Order) == -1 {
			break
		}
		sk.SetBytes(common.Hash4Bls(sk.Bytes()))
	}
	return sk
}

// BLSPKGen take a secret key and return BLS public key
func BLSPKGen(sk *big.Int) *bn256.G2 {
	pk := new(bn256.G2)
	pk = pk.ScalarBaseMult(sk)
	return pk
}

// PKBytes take input publickey point and return publickey bytes
func PKBytes(pk *bn256.G2) PublicKey {
	return pk.Marshal()
}
