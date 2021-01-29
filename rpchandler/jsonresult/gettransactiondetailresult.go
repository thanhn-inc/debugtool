package jsonresult

import (
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/privacy/coin"
	"strconv"
)

type TransactionDetail struct {
	BlockHash   string `json:"BlockHash"`
	BlockHeight uint64 `json:"BlockHeight"`
	TxSize      uint64 `json:"TxSize"`
	Index       uint64 `json:"Index"`
	ShardID     byte   `json:"ShardID"`
	Hash        string `json:"Hash"`
	Version     int8   `json:"Version"`
	Type        string `json:"Type"` // Transaction type
	LockTime    string `json:"LockTime"`
	Fee         uint64 `json:"Fee"` // Fee applies: always consant
	Image       string `json:"Image"`

	IsPrivacy       bool          `json:"IsPrivacy"`
	Proof           privacy.Proof `json:"Proof"`
	ProofDetail     ProofDetail   `json:"ProofDetail"`
	InputCoinPubKey string        `json:"InputCoinPubKey"`
	SigPubKey       string        `json:"SigPubKey,omitempty"` // 64 bytes
	Sig             string        `json:"Sig,omitempty"`       // 64 bytes

	Metadata                      string      `json:"Metadata"`
	CustomTokenData               string      `json:"CustomTokenData"`
	PrivacyCustomTokenID          string      `json:"PrivacyCustomTokenID"`
	PrivacyCustomTokenName        string      `json:"PrivacyCustomTokenName"`
	PrivacyCustomTokenSymbol      string      `json:"PrivacyCustomTokenSymbol"`
	PrivacyCustomTokenData        string      `json:"PrivacyCustomTokenData"`
	PrivacyCustomTokenProofDetail ProofDetail `json:"PrivacyCustomTokenProofDetail"`
	PrivacyCustomTokenIsPrivacy   bool        `json:"PrivacyCustomTokenIsPrivacy"`
	PrivacyCustomTokenFee         uint64      `json:"PrivacyCustomTokenFee"`

	IsInMempool bool `json:"IsInMempool"`
	IsInBlock   bool `json:"IsInBlock"`

	Info string `json:"Info"`
}

type ProofDetail struct {
	InputCoins  []CoinRPC
	OutputCoins []CoinRPC
}

func (proofDetail *ProofDetail) ConvertFromProof(proof privacy.Proof) {
	inputCoins := proof.GetInputCoins()
	outputCoins := proof.GetOutputCoins()

	proofDetail.InputCoins = make([]CoinRPC, len(inputCoins))
	for i, input := range inputCoins {
		proofDetail.InputCoins[i] = ParseCoinRPCInput(input)
	}

	proofDetail.OutputCoins = make([]CoinRPC, len(outputCoins))
	for i, output := range outputCoins {
		proofDetail.OutputCoins[i] = ParseCoinRPCOutput(output)
	}
}

func ParseCoinRPCInput(inputCoin coin.PlainCoin) CoinRPC {
	var coinrpc CoinRPC
	if inputCoin.GetVersion() == 1 {
		coinrpc = new(CoinRPCV1)
	} else {
		coinrpc = new(CoinRPCV2)
	}
	return coinrpc.SetInputCoin(inputCoin)
}

func ParseCoinRPCOutput(outputCoin coin.Coin) CoinRPC {
	var coinrpc CoinRPC
	if outputCoin.GetVersion() == 1 {
		coinrpc = new(CoinRPCV1)
	} else {
		coinrpc = new(CoinRPCV2)
	}
	return coinrpc.SetOutputCoin(outputCoin)
}

type CoinRPC interface {
	SetInputCoin(coin.PlainCoin) CoinRPC
	SetOutputCoin(coin.Coin) CoinRPC
}


func privacyPointPtrToBase58(point *privacy.Point) string {
	if point == nil || point.IsIdentity()  {
		return ""
	} else {
		return EncodeBase58Check(point.ToBytesS())
	}
}

func privacyScalarPtrToBase58(scalar *privacy.Scalar) string {
	if scalar == nil {
		return ""
	} else {
		return EncodeBase58Check(scalar.ToBytesS())
	}
}

func (c *CoinRPCV1) SetInputCoin(inputCoin coin.PlainCoin) CoinRPC {
	coinv1 := inputCoin.(*coin.PlainCoinV1)

	c.Version = coinv1.GetVersion()
	c.PublicKey = privacyPointPtrToBase58(coinv1.GetPublicKey())
	c.Commitment = privacyPointPtrToBase58(coinv1.GetCommitment())
	c.SNDerivator = privacyScalarPtrToBase58(coinv1.GetSNDerivator())
	c.KeyImage = privacyPointPtrToBase58(coinv1.GetKeyImage())
	c.Randomness = privacyScalarPtrToBase58(coinv1.GetRandomness())
	c.Value = coinv1.GetValue()
	c.Info = EncodeBase58Check(coinv1.GetInfo())
	return c
}

func (c *CoinRPCV1) SetOutputCoin(inputCoin coin.Coin) CoinRPC {
	coinv1 := inputCoin.(*coin.CoinV1)

	c.Version = coinv1.GetVersion()
	c.PublicKey = privacyPointPtrToBase58(coinv1.GetPublicKey())
	c.Commitment = privacyPointPtrToBase58(coinv1.GetCommitment())
	c.SNDerivator = privacyScalarPtrToBase58(coinv1.GetSNDerivator())
	c.KeyImage = privacyPointPtrToBase58(coinv1.GetKeyImage())
	c.Randomness = privacyScalarPtrToBase58(coinv1.GetRandomness())
	c.Value = coinv1.CoinDetails.GetValue()
	c.Info = EncodeBase58Check(coinv1.GetInfo())
	if coinv1.CoinDetailsEncrypted != nil {
		c.CoinDetailsEncrypted = EncodeBase58Check(coinv1.CoinDetailsEncrypted.Bytes())
	} else {
		c.CoinDetailsEncrypted = ""
	}
	return c
}

func (c *CoinRPCV2) SetInputCoin(inputCoin coin.PlainCoin) CoinRPC {
	return c.SetOutputCoin(inputCoin.(coin.Coin))
}

func (c *CoinRPCV2) SetOutputCoin(outputCoin coin.Coin) CoinRPC {
	coinv2 := outputCoin.(*coin.CoinV2)

	c.Version = coinv2.GetVersion()
	c.Info = EncodeBase58Check(coinv2.GetInfo())
	c.PublicKey = privacyPointPtrToBase58(coinv2.GetPublicKey())
	c.Commitment = privacyPointPtrToBase58(coinv2.GetCommitment())
	c.KeyImage = privacyPointPtrToBase58(coinv2.GetKeyImage())
	c.TxRandom = EncodeBase58Check(coinv2.GetTxRandom().Bytes())
	c.Value = strconv.FormatUint(coinv2.GetValue(), 10)
	c.Randomness = privacyScalarPtrToBase58(coinv2.GetRandomness())
	//txRandomPoint, index, _ := coinv2.GetTxRandomDetail()
	//c.TxRandom = privacyPointPtrToBase58(txRandomPoint)
	//c.Index = index

	return c
}

type CoinRPCV1 struct {
	Version              uint8
	PublicKey            string
	Commitment           string
	SNDerivator          string
	KeyImage             string
	Randomness           string
	Value                uint64
	Info                 string
	CoinDetailsEncrypted string
}

type CoinRPCV2 struct {
	Version    uint8
	Index      uint32
	Info       string
	PublicKey  string
	Commitment string
	KeyImage   string
	TxRandom   string

	Value 		 string
	Randomness   string
}
