package coin

import (
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/privacy/key"
	"github.com/thanhn-inc/debugtool/privacy/operation"
	"github.com/thanhn-inc/debugtool/wallet"
)

const (
	MaxSizeInfoCoin   = 255
	JsonMarshalFlag   = 34
	CoinVersion1      = 1
	CoinVersion2      = 2
	TxRandomGroupSize = 68
)

const (
	PedersenPrivateKeyIndex = operation.PedersenPrivateKeyIndex
	PedersenValueIndex      = operation.PedersenValueIndex
	PedersenSndIndex        = operation.PedersenSndIndex
	PedersenShardIDIndex    = operation.PedersenShardIDIndex
	PedersenRandomnessIndex = operation.PedersenRandomnessIndex
)

func getMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseScalarForSetBytes(coinBytes *[]byte, offset *int) (*operation.Scalar, error) {
	b := *coinBytes
	if *offset >= len(b) {
		return nil, errors.New("Offset is larger than len(bytes), cannot parse scalar")
	}
	var sc *operation.Scalar = nil
	lenField := b[*offset]
	*offset += 1
	if lenField != 0 {
		if *offset+int(lenField) > len(b) {
			return nil, errors.New("Offset+curLen is larger than len(bytes), cannot parse scalar for set bytes")
		}
		data := b[*offset : *offset+int(lenField)]
		sc = new(operation.Scalar).FromBytesS(data)
		*offset += int(lenField)
	}
	return sc, nil
}

func parsePointForSetBytes(coinBytes *[]byte, offset *int) (*operation.Point, error) {
	b := *coinBytes
	if *offset >= len(b) {
		return nil, errors.New("Offset is larger than len(bytes), cannot parse point")
	}
	var point *operation.Point = nil
	var err error
	lenField := b[*offset]
	*offset += 1
	if lenField != 0 {
		if *offset+int(lenField) > len(b) {
			return nil, errors.New("Offset+curLen is larger than len(bytes), cannot parse point for set bytes")
		}
		data := b[*offset : *offset+int(lenField)]
		point, err = new(operation.Point).FromBytesS(data)
		if err != nil {
			return nil, err
		}
		*offset += int(lenField)
	}
	return point, nil
}

func parseInfoForSetBytes(coinBytes *[]byte, offset *int) ([]byte, error) {
	b := *coinBytes
	if *offset >= len(b) {
		return []byte{}, errors.New("Offset is larger than len(bytes), cannot parse info")
	}
	info := []byte{}
	lenField := b[*offset]
	*offset += 1
	if lenField != 0 {
		if *offset+int(lenField) > len(b) {
			return []byte{}, errors.New("Offset+curLen is larger than len(bytes), cannot parse info for set bytes")
		}
		info = make([]byte, lenField)
		copy(info, b[*offset:*offset+int(lenField)])
		*offset += int(lenField)
	}
	return info, nil
}

func NewCoinFromPaymentInfo(info *key.PaymentInfo) (*CoinV2, error) {
	receiverPublicKey, err := new(operation.Point).FromBytesS(info.PaymentAddress.Pk)
	if err != nil {
		errStr := fmt.Sprintf("Cannot parse outputCoinV2 from PaymentInfo when parseByte PublicKey, error %v ", err)
		return nil, errors.New(errStr)
	}
	receiverPublicKeyBytes := receiverPublicKey.ToBytesS()
	targetShardID := common.GetShardIDFromLastByte(receiverPublicKeyBytes[len(receiverPublicKeyBytes)-1])

	c := new(CoinV2).Init()
	// Amount, Randomness, SharedRandom are transparency until we call concealData
	c.SetAmount(new(operation.Scalar).FromUint64(info.Amount))
	c.SetRandomness(operation.RandomScalar())
	c.SetSharedRandom(operation.RandomScalar()) // shared randomness for creating one-time-address
	c.SetSharedConcealRandom(operation.RandomScalar()) //shared randomness for concealing amount and blinding asset tag
	c.SetInfo(info.Message)
	c.SetCommitment(operation.PedCom.CommitAtIndex(c.GetAmount(), c.GetRandomness(), operation.PedersenValueIndex))

	// If this is going to burning address then dont need to create ota
	if wallet.IsPublicKeyBurningAddress(info.PaymentAddress.Pk) {
		publicKey, err := new(operation.Point).FromBytesS(info.PaymentAddress.Pk)
		if err != nil {
			panic("Something is wrong with info.paymentAddress.pk, burning address should be a valid point")
		}
		c.SetPublicKey(publicKey)
		return c, nil
	}

	// Increase index until have the right shardID
	index := uint32(0)
	publicOTA := info.PaymentAddress.GetOTAPublicKey()
	if publicOTA == nil {
		return nil, errors.New("public OTA from payment address is nil")
	}
	publicSpend := info.PaymentAddress.GetPublicSpend()
	rK := new(operation.Point).ScalarMult(publicOTA, c.GetSharedRandom())
	for {
		index += 1

		// Get publickey
		hash := operation.HashToScalar(append(rK.ToBytesS(), common.Uint32ToBytes(index)...))
		HrKG := new(operation.Point).ScalarMultBase(hash)
		publicKey := new(operation.Point).Add(HrKG, publicSpend)
		c.SetPublicKey(publicKey)

		currentShardID, err := c.GetShardID()
		if err != nil {
			return nil, err
		}
		if currentShardID == targetShardID {
			otaRandomPoint := new(operation.Point).ScalarMultBase(c.GetSharedRandom())
			concealRandomPoint := new(operation.Point).ScalarMultBase(c.GetSharedConcealRandom())
			c.SetTxRandomDetail(concealRandomPoint, otaRandomPoint, index)
			break
		}
	}
	return c, nil
}

func NewCoinFromAmountAndTxRandomBytes(amount uint64, publicKey *operation.Point, txRandom *TxRandom, info []byte) *CoinV2 {
	c := new(CoinV2).Init()
	c.SetPublicKey(publicKey)
	c.SetAmount(new(operation.Scalar).FromUint64(amount))
	c.SetRandomness(operation.RandomScalar())
	c.SetTxRandom(txRandom)
	c.SetCommitment(operation.PedCom.CommitAtIndex(c.GetAmount(), c.GetRandomness(), operation.PedersenValueIndex))
	c.SetSharedRandom(nil)
	c.SetInfo(info)
	return c
}