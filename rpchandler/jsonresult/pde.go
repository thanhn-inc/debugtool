package jsonresult

import (
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"sort"
)

// key prefix
var (
	// PDE
	WaitingPDEContributionPrefix = []byte("waitingpdecontribution-")
	PDEPoolPrefix                = []byte("pdepool-")
	PDESharePrefix               = []byte("pdeshare-")
	PDETradingFeePrefix          = []byte("pdetradingfee-")
	PDETradeFeePrefix            = []byte("pdetradefee-")
	PDEContributionStatusPrefix  = []byte("pdecontributionstatus-")
	PDETradeStatusPrefix         = []byte("pdetradestatus-")
	PDEWithdrawalStatusPrefix    = []byte("pdewithdrawalstatus-")
	PDEFeeWithdrawalStatusPrefix = []byte("pdefeewithdrawalstatus-")
)

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

func BuildPDEPoolForPairKey(
	beaconHeight uint64,
	token1IDStr string,
	token2IDStr string,
) []byte {
	beaconHeightBytes := []byte(fmt.Sprintf("%d-", beaconHeight))
	pdePoolForPairByBCHeightPrefix := append(PDEPoolPrefix, beaconHeightBytes...)
	tokenIDStrs := []string{token1IDStr, token2IDStr}
	sort.Strings(tokenIDStrs)
	return append(pdePoolForPairByBCHeightPrefix, []byte(tokenIDStrs[0]+"-"+tokenIDStrs[1])...)
}
