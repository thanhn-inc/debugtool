package jsonresult

import "github.com/thanhn-inc/debugtool/common"

type CurrentPDEState struct {
	WaitingPDEContributions map[string]*PDEContribution `json:"WaitingPDEContributions"`
	PDEPoolPairs            map[string]*PDEPoolForPair  `json:"PDEPoolPairs"`
	PDEShares               map[string]uint64           `json:"PDEShares"`
	PDETradingFees          map[string]uint64           `json:"PDETradingFees"`
	BeaconTimeStamp         int64                       `json:"BeaconTimeStamp"`
}

type PDEPoolForPair struct {
	Token1IDStr     string
	Token1PoolValue uint64
	Token2IDStr     string
	Token2PoolValue uint64
}

type PDEContribution struct {
	ContributorAddressStr string
	TokenIDStr            string
	Amount                uint64
	TxReqID               common.Hash
}
