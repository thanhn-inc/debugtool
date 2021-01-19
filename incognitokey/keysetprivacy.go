package incognitokey

import (
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/privacy/key"
)

// KeySet is real raw data of wallet account, which user can use to
// - spend and check double spend coin with private key
// - receive coin with payment address
// - read tx data with readonly key
type KeySet struct {
	PrivateKey     key.PrivateKey //Master Private key
	PaymentAddress key.PaymentAddress //Payment address for sending coins
	ReadonlyKey    key.ViewingKey	//ViewingKey for retrieving the amount of coin (both V1 + V2) as well as the asset tag (V2 ONLY)
	OTAKey 		   key.OTAKey  //OTAKey is for recovering one time addresses: ONLY in V2
}

// GenerateKey generates key set from seed in byte array
func (keySet *KeySet) GenerateKey(seed []byte) *KeySet {
	keySet.PrivateKey = key.GeneratePrivateKey(seed)
	keySet.PaymentAddress = key.GeneratePaymentAddress(keySet.PrivateKey[:])
	keySet.ReadonlyKey = key.GenerateViewingKey(keySet.PrivateKey[:])
	keySet.OTAKey = key.GenerateOTAKey(keySet.PrivateKey[:])
	return keySet
}

// InitFromPrivateKeyByte receives private key in bytes array,
// and regenerates payment address and readonly key
// returns error if private key is invalid
func (keySet *KeySet) InitFromPrivateKeyByte(privateKey []byte) error {
	if len(privateKey) != common.PrivateKeySize {
		return NewCashecError(InvalidPrivateKeyErr, nil)
	}

	keySet.PrivateKey = privateKey
	keySet.PaymentAddress = key.GeneratePaymentAddress(keySet.PrivateKey[:])
	keySet.ReadonlyKey = key.GenerateViewingKey(keySet.PrivateKey[:])
	keySet.OTAKey = key.GenerateOTAKey(keySet.PrivateKey[:])
	return nil
}

// InitFromPrivateKey receives private key in PrivateKey type,
// and regenerates payment address and readonly key
// returns error if private key is invalid
func (keySet *KeySet) InitFromPrivateKey(privateKey *key.PrivateKey) error {
	if privateKey == nil || len(*privateKey) != common.PrivateKeySize {
		return NewCashecError(InvalidPrivateKeyErr, nil)
	}

	keySet.PrivateKey = *privateKey
	keySet.PaymentAddress = key.GeneratePaymentAddress(keySet.PrivateKey[:])
	keySet.ReadonlyKey = key.GenerateViewingKey(keySet.PrivateKey[:])
	keySet.OTAKey = key.GenerateOTAKey(keySet.PrivateKey[:])

	return nil
}

//// Sign receives data in bytes array and
//// returns the signature of that data using Schnorr Signature Scheme with signing key is private key in ketSet
//func (keySet KeySet) Sign(data []byte) ([]byte, error) {
//	if len(data) == 0 {
//		return []byte{}, NewCashecError(InvalidDataSignErr, errors.New("data is empty to sign"))
//	}
//
//	hash := common.HashB(data)
//	privateKeySig := new(schnorr.SchnorrPrivateKey)
//	privateKeySig.Set(new(operation.Scalar).FromBytesS(keySet.PrivateKey), new(operation.Scalar).FromUint64(0))
//
//	signature, err := privateKeySig.Sign(hash)
//	if err != nil {
//		return []byte{}, NewCashecError(SignError, err)
//	}
//	return signature.Bytes(), nil
//}

//// Verify receives data and signature
//// It checks whether the given signature is the signature of data
//// and was signed by private key corresponding to public key in keySet or not
//func (keySet KeySet) Verify(data, signature []byte) (bool, error) {
//	hash := common.HashB(data)
//	isValid := false
//
//	pubKeySig := new(schnorr.SchnorrPublicKey)
//	PK, err := new(operation.Point).FromBytesS(keySet.PaymentAddress.Pk)
//	if err != nil {
//		return false, NewCashecError(InvalidVerificationKeyErr, nil)
//	}
//	pubKeySig.Set(PK)
//
//	signatureSetBytes := new(schnorr.SchnSignature)
//	err = signatureSetBytes.SetBytes(signature)
//	if err != nil {
//		return false, err
//	}
//
//	isValid = pubKeySig.Verify(signatureSetBytes, hash)
//	return isValid, nil
//}

// GetPublicKeyInBase58CheckEncode returns the public key which is base58 check encoded
func (keySet KeySet) GetPublicKeyInBase58CheckEncode() string {
	return base58.Base58Check{}.Encode(keySet.PaymentAddress.Pk, common.ZeroByte)
}

func (keySet KeySet) GetReadOnlyKeyInBase58CheckEncode() string {
	return base58.Base58Check{}.Encode(keySet.ReadonlyKey.Rk, common.ZeroByte)
}

func (keySet KeySet) GetOTASecretKeyInBase58CheckEncode() string {
	return base58.Base58Check{}.Encode(keySet.OTAKey.GetOTASecretKey().ToBytesS(), common.ZeroByte)
}