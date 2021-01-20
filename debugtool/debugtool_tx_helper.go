package debugtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/jsonresult"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/transaction/utils"
	"github.com/thanhn-inc/debugtool/wallet"
	"sort"
)

const DefaultPRVFee = uint64(100)

//Create payment info lists based on the provided address list and corresponding amount list.
func CreatePaymentInfos(addrList []string, amountList []uint64) ([]*privacy.PaymentInfo, error) {
	if len(addrList) != len(amountList) {
		return nil, errors.New(fmt.Sprintf("length of payment address (%) and length amount (%) mismatch.", len(addrList), len(amountList)))
	}

	paymentInfos := make([]*privacy.PaymentInfo, 0)
	for i, addr := range addrList {
		receiverWallet, err := wallet.Base58CheckDeserialize(addr)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("cannot deserialize key %v: %v", addr, err))
		}
		paymentInfo := privacy.PaymentInfo{PaymentAddress: receiverWallet.KeySet.PaymentAddress, Amount: amountList[i], Message: []byte{}}
		paymentInfos = append(paymentInfos, &paymentInfo)
	}

	return paymentInfos, nil
}

//Choose best UTXOs to spend depending on the provided amount.
//
//Assume that the input coins have be sorted in the descending order.
func ChooseBestCoinsByAmount(coinList []privacy.PlainCoin, requiredAmount uint64) ([]privacy.PlainCoin, error) {
	totalInputAmount := uint64(0)
	for _, inputCoin := range coinList {
		totalInputAmount += inputCoin.GetValue()
	}

	if totalInputAmount < requiredAmount {
		return nil, errors.New(fmt.Sprintf("total unspent amount (%v) is less than the required requiredAmount (%v)", totalInputAmount, requiredAmount))
	}

	if totalInputAmount == requiredAmount {
		return coinList, nil
	}

	coinsToSpend := make([]privacy.PlainCoin, 0)
	remainAmount := requiredAmount
	totalChosenAmount := uint64(0)
	//TODO: find a better solution for this.
	for i := 0; i < len(coinList)-1; i++ {
		if coinList[i].GetValue() > remainAmount {
			if coinList[i+1].GetValue() > remainAmount {
				continue
			} else {
				coinsToSpend = append(coinsToSpend, coinList[i])
				totalChosenAmount += coinList[i].GetValue()
				break
			}
		} else {
			coinsToSpend = append(coinsToSpend, coinList[i])
			remainAmount -= coinList[i].GetValue()
			totalChosenAmount += coinList[i].GetValue()
		}
	}

	fmt.Printf("totalChosenAmount: %v, requireAmount: %v\n", totalChosenAmount, requiredAmount)

	if totalChosenAmount < requiredAmount {
		totalChosenAmount += coinList[len(coinList)-1].GetValue()
		coinsToSpend = append(coinsToSpend, coinList[len(coinList)-1])
		if totalChosenAmount < requiredAmount {
			return nil, errors.New("not enough coin to spend")
		}
	}

	fmt.Println("number of coins to spend:", len(coinsToSpend))

	return coinsToSpend, nil
}

//Divide list of coins w.r.t their version and sort them by values if needed.
func DivideCoins(coinList []privacy.PlainCoin, needSorted bool) ([]privacy.PlainCoin, []privacy.PlainCoin, error) {
	coinV1List := make([]privacy.PlainCoin, 0)
	coinV2List := make([]privacy.PlainCoin, 0)
	for _, inputCoin := range coinList {
		if inputCoin.GetVersion() == 2 {
			tmpCoin, ok := inputCoin.(*privacy.CoinV2)
			if !ok {
				return nil, nil, errors.New(fmt.Sprintf("cannot parse coinV2"))
			}

			coinV2List = append(coinV2List, tmpCoin)
		} else {
			tmpCoin, ok := inputCoin.(*privacy.PlainCoinV1)
			if !ok {
				return nil, nil, errors.New(fmt.Sprintf("cannot parse coinV2"))
			}

			coinV1List = append(coinV1List, tmpCoin)
		}
	}

	if needSorted {
		sort.Slice(coinV1List, func(i, j int) bool {
			return coinV1List[i].GetValue() > coinV1List[j].GetValue()
		})

		sort.Slice(coinV2List, func(i, j int) bool {
			return coinV2List[i].GetValue() > coinV2List[j].GetValue()
		})
	}

	return coinV1List, coinV2List, nil
}

func GetRandomCommitments(inputCoins []privacy.PlainCoin, tokenID string) (map[string]interface{}, error) {
	if len(inputCoins) == 0 {
		return nil, errors.New("no input coin to retrieve random commitments")
	}
	outCoinList := make([]jsonresult.OutCoin, 0)
	for _, inputCoin := range inputCoins {
		outCoin := jsonresult.NewOutCoin(inputCoin)
		outCoinList = append(outCoinList, outCoin)
	}

	lastByte := inputCoins[0].GetPublicKey().ToBytesS()[len(inputCoins[0].GetPublicKey().ToBytesS())-1]
	shardID := common.GetShardIDFromLastByte(lastByte)

	responseInBytes, err := rpc.RandomCommitments(shardID, outCoinList, tokenID)
	if err != nil {
		return nil, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return nil, err
	}

	var randomCommitment jsonresult.RandomCommitmentResult
	err = json.Unmarshal(response.Result, &randomCommitment)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("parse randomCommitment error: %v", err))
	}

	commitmentList := make([]*privacy.Point, 0)
	for _, commitmentStr := range randomCommitment.Commitments {
		cmtBytes, _, err := base58.Base58Check{}.Decode(commitmentStr)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("cannot decode commitment %v: %v", commitmentStr, err))
		}

		commitment, err := new(privacy.Point).FromBytesS(cmtBytes)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("cannot parse commitment %v: %v", cmtBytes, err))
		}

		commitmentList = append(commitmentList, commitment)
	}

	result := make(map[string]interface{})
	result[utils.CommitmentIndices] = randomCommitment.CommitmentIndices
	result[utils.MyCommitmentIndices] = randomCommitment.MyCommitmentIndexs
	result[utils.Commitments] = commitmentList

	return result, nil
}
