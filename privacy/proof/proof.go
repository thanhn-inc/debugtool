package proof

import (
	"github.com/thanhn-inc/debugtool/privacy/coin"
	errhandler "github.com/thanhn-inc/debugtool/privacy/errorhandler"
	"github.com/thanhn-inc/debugtool/privacy/proof/agg_interface"
)

// Paymentproof
type Proof interface {
	GetVersion() uint8
	Init()
	GetInputCoins() []coin.PlainCoin
	GetOutputCoins() []coin.Coin
	GetAggregatedRangeProof() agg_interface.AggregatedRangeProof

	SetInputCoins([]coin.PlainCoin) error
	SetOutputCoins([]coin.Coin) error

	Bytes() []byte
	SetBytes(proofBytes []byte) *errhandler.PrivacyError

	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error

	IsPrivacy() bool
}

