package debugtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/metadata"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/jsonresult"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/wallet"
)

func CreatePDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64, version int8) ([]byte, string, error) {
	if version == 2 {
		return CreatePDETradeTransactionVer2(privateKey, tokenIDToSell, tokenIDToBuy, amount)
	} else if version == 1{
		return CreatePDETradeTransactionVer1(privateKey, tokenIDToSell, tokenIDToBuy, amount)
	} else {//Try either one of the version, if possible
		encodedTx, txHash, err := CreatePDETradeTransactionVer1(privateKey, tokenIDToSell, tokenIDToBuy, amount)
		if err != nil {
			fmt.Println("CreatePDETradeTransactionVer1 error:", err)
			encodedTx, txHash, err1 := CreatePDETradeTransactionVer2(privateKey, tokenIDToSell, tokenIDToBuy, amount)
			if err1 != nil {
				return nil, "", errors.New(fmt.Sprintf("cannot create raw pdetradetransaction for either version: %v, %v", err, err1))
			}
			return encodedTx, txHash, nil
		}
		return encodedTx, txHash, nil
	}
}
func CreatePDETradeTransactionVer1(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	minAccept := uint64(1)
	//uncomment this code if you want to get the best price
	minAccept, err = CheckPrice(tokenIDToSell, tokenIDToBuy, amount)
	if err != nil {
		return nil, "", err
	}
	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	var pdeTradeMetadata *metadata.PDETradeRequest
	if tokenIDToSell == common.PRVIDStr || tokenIDToBuy == common.PRVIDStr {
		pdeTradeMetadata, err = metadata.NewPDETradeRequest(tokenIDToBuy, tokenIDToSell, amount, minAccept, 0,
			addr, "", metadata.PDETradeRequestMeta)
	} else {
		pdeTradeMetadata, err = metadata.NewPDETradeRequest(tokenIDToBuy, tokenIDToSell, amount, minAccept, 0,
			addr, "", metadata.PDECrossPoolTradeRequestMeta)
	}
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init trade request for %v to %v with amount %v: %v", tokenIDToSell, tokenIDToBuy, amount, err))
	}

	txParam := NewTxParam(privateKey, []string{common.BurningAddress2}, []uint64{amount}, tokenIDToSell, 1, pdeTradeMetadata)
	if tokenIDToSell == common.PRVIDStr {
		return CreateRawTransaction(txParam, 1)
	} else {
		//Trade token will use token to pay fee (in case of txtokenver1)
		kvargs := make(map[string]interface{})
		kvargs["hasTokenFee"] = true
		txParam.SetKvargs(kvargs)
		return CreateRawTokenTransaction(txParam, 1)
	}
}
func CreatePDETradeTransactionVer2(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	minAccept := uint64(1)
	////uncomment this code if you want to get the best price
	//minAccept, err = CheckPrice(tokenIDToSell, tokenIDToBuy, amount)
	//if err != nil {
	//	return nil, "", err
	//}
	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	pubKeyStr, txRandomStr, err := GenerateOTAFromPaymentAddress(addr)
	if err != nil {
		return nil, "", err
	}

	var pdeTradeMetadata *metadata.PDETradeRequest
	if tokenIDToSell == common.PRVIDStr || tokenIDToBuy == common.PRVIDStr {
		pdeTradeMetadata, err = metadata.NewPDETradeRequest(tokenIDToBuy, tokenIDToSell, amount, minAccept, 0,
			pubKeyStr, txRandomStr, metadata.PDETradeRequestMeta)
	} else {
		pdeTradeMetadata, err = metadata.NewPDETradeRequest(tokenIDToBuy, tokenIDToSell, amount, minAccept, 0,
			pubKeyStr, txRandomStr, metadata.PDECrossPoolTradeRequestMeta)
	}
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init trade request for %v to %v with amount %v: %v", tokenIDToSell, tokenIDToBuy, amount, err))
	}

	txParam := NewTxParam(privateKey, []string{common.BurningAddress2}, []uint64{amount}, tokenIDToSell, 1, pdeTradeMetadata)
	if tokenIDToSell == common.PRVIDStr {
		return CreateRawTransaction(txParam, 2)
	} else {
		return CreateRawTokenTransaction(txParam, 2)
	}

}
func CreateAndSendPDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64) (string, error) {
	encodedTx, txHash, err := CreatePDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy, amount, -1)
	if err != nil {
		return "", err
	}

	var responseInBytes []byte
	if tokenIDToSell == common.PRVIDStr {
		responseInBytes, err = rpc.SendRawTx(string(encodedTx))
		if err != nil {
			return "", err
		}
	} else {
		responseInBytes, err = rpc.SendRawTokenTx(string(encodedTx))
		if err != nil {
			return "", err
		}
	}


	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	//fmt.Printf("CreateAndSendPDETradeTransaction succeeded: %v\n", txHash)

	////Checking if the tokenToBuy has been received
	//start := time.Now()
	//oldBalance, err := GetBalance(privateKey, tokenIDToSell)
	//if err != nil {
	//	return txHash, err
	//}
	//for {
	//	isInBlock, err := CheckTxInBlock(txHash)
	//	if err != nil {
	//		return txHash, err
	//	}
	//	if !isInBlock {
	//		if time.Since(start).Seconds() > 900 {
	//			fmt.Println("Abort because of timeout")
	//			return txHash, fmt.Errorf("abort because of timeout")
	//		} else {
	//			fmt.Println("sleep 10 seconds...")
	//			time.Sleep(10 * time.Second)
	//		}
	//	} else {
	//		fmt.Println("start checking balance tokenToBuy...")
	//		for {
	//			newBalance, err := GetBalance(privateKey, tokenIDToBuy)
	//			if err != nil {
	//				return txHash, err
	//			}
	//
	//			if newBalance - oldBalance > 0 {
	//				fmt.Printf("balance updated: %v\n", newBalance)
	//				break
	//			} else {
	//				if time.Since(start).Seconds() > 900 {
	//					fmt.Println("Abort because of timeout")
	//					return txHash, fmt.Errorf("abort because of timeout")
	//				} else {
	//					fmt.Println("sleep 10 seconds for checking balance...")
	//					time.Sleep(10 * time.Second)
	//				}
	//			}
	//		}
	//		break
	//	}
	//}

	return txHash, nil
}

func CreatePDEContributeTransaction(privateKey, pairID, tokenID string, amount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	md, err := metadata.NewPDEContribution(pairID, addr, amount, tokenID, metadata.PDEContributionMeta)

	txParam := NewTxParam(privateKey, []string{common.BurningAddress2}, []uint64{amount}, tokenID, 1, md)

	if tokenID == common.PRVIDStr {
		return CreateRawTransaction(txParam, -1)
	} else {
		return CreateRawTokenTransaction(txParam, -1)
	}
}
func CreateAndSendPDEContributeTransaction(privateKey, pairID, tokenID string, amount uint64) (string, error) {
	encodedTx, txHash, err := CreatePDEContributeTransaction(privateKey, pairID, tokenID, amount)
	if err != nil {
		return "", err
	}

	var responseInBytes []byte
	if tokenID == common.PRVIDStr {
		responseInBytes, err = rpc.SendRawTx(string(encodedTx))
		if err != nil {
			return "", err
		}
	} else {
		responseInBytes, err = rpc.SendRawTokenTx(string(encodedTx))
		if err != nil {
			return "", err
		}
	}


	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

func CreatePDEWithdrawalTransaction(privateKey, tokenID1, tokenID2 string, sharedAmount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	pdeTradeMetadata, err := metadata.NewPDEWithdrawalRequest(addr, tokenID2, tokenID1, sharedAmount, metadata.PDEWithdrawalRequestMeta)

	txParam := NewTxParam(privateKey, []string{}, []uint64{}, common.PRVIDStr, 0, pdeTradeMetadata)

	return CreateRawTransaction(txParam, -1)
}
func CreateAndSendPDEWithdrawalTransaction(privateKey, tokenID1, tokenID2 string, sharedAmount uint64) (string, error) {
	encodedTx, txHash, err := CreatePDEWithdrawalTransaction(privateKey, tokenID1, tokenID2, sharedAmount)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTx(string(encodedTx))
	if err != nil {
		return "", err
	}

	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

func GetCurrentPDEState(beaconHeight uint64) (*jsonresult.CurrentPDEState, error){
	responseInBytes, err := rpc.GetPDEState(beaconHeight)
	if err != nil {
		return nil, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return nil, err
	}

	var pdeState jsonresult.CurrentPDEState
	err = json.Unmarshal(response.Result, &pdeState)
	if err != nil {
		return nil, err
	}

	return &pdeState, nil
}

func GetAllPDEPoolPairs(beaconHeight uint64) (map[string]*jsonresult.PDEPoolForPair, error) {
	pdeState, err := GetCurrentPDEState(beaconHeight)
	if err != nil {
		return nil, err
	}

	fmt.Println("number of poolpairs:", len(pdeState.PDEPoolPairs))

	return pdeState.PDEPoolPairs, nil
}

func GetPDEPoolPair(beaconHeight uint64, tokenID1, tokenID2 string) (*jsonresult.PDEPoolForPair, error) {
	allPoolPairs, err := GetAllPDEPoolPairs(beaconHeight)
	if err != nil {
		return nil, err
	}

	keyPool := jsonresult.BuildPDEPoolForPairKey(beaconHeight, tokenID1, tokenID2)
	if poolPair, ok := allPoolPairs[string(keyPool)]; ok {
		return poolPair, nil
	}

	return nil, errors.New(fmt.Sprintf("cannot found pool pair for tokenID %v and %v.", tokenID1, tokenID2))
}

//Get trade value buy calculating things at local machine
func GetTradeValue(tokenToSell, TokenToBuy string, sellAmount uint64) (uint64, error) {
	bestBlocks, err := GetBestBlock()
	if err != nil {
		return 0, err
	}

	bestBeaconHeight := bestBlocks[-1]

	poolPair, err := GetPDEPoolPair(bestBeaconHeight, tokenToSell, TokenToBuy)
	if err != nil {
		return 0, err
	}

	var sellPoolAmount, buyPoolAmount uint64
	if poolPair.Token1IDStr == tokenToSell {
		sellPoolAmount = poolPair.Token1PoolValue
		buyPoolAmount = poolPair.Token2PoolValue
	} else {
		sellPoolAmount = poolPair.Token2PoolValue
		buyPoolAmount = poolPair.Token1PoolValue
	}

	return UniswapValue(sellAmount, sellPoolAmount, buyPoolAmount)
}

func GetXTradeValue(tokenToSell, tokenToBuy string, sellAmount uint64) (uint64, error) {
	bestBlocks, err := GetBestBlock()
	if err != nil {
		return 0, err
	}

	bestBeaconHeight := bestBlocks[-1]

	allPoolPairs, err := GetAllPDEPoolPairs(bestBeaconHeight)
	if err != nil {
		return 0, err
	}

	keyPool1 := jsonresult.BuildPDEPoolForPairKey(bestBeaconHeight, tokenToSell, common.PRVIDStr)
	keyPool2 := jsonresult.BuildPDEPoolForPairKey(bestBeaconHeight, common.PRVIDStr, tokenToBuy)

	var poolPair1, poolPair2 *jsonresult.PDEPoolForPair
	var ok bool
	if poolPair1, ok = allPoolPairs[string(keyPool1)]; !ok {
		return 0, fmt.Errorf("cannot found pool pair %v - %v", tokenToSell, common.PRVIDStr)
	}
	if poolPair2, ok = allPoolPairs[string(keyPool2)]; !ok {
		return 0, fmt.Errorf("cannot found pool pair %v - %v", common.PRVIDStr, tokenToBuy)
	}

	var sellPoolAmount1, buyPoolAmount1 uint64
	if poolPair1.Token1IDStr == tokenToSell {
		sellPoolAmount1 = poolPair1.Token1PoolValue
		buyPoolAmount1 = poolPair1.Token2PoolValue
	} else {
		sellPoolAmount1 = poolPair1.Token2PoolValue
		buyPoolAmount1 = poolPair1.Token1PoolValue
	}

	expectPRV, err := UniswapValue(sellAmount, sellPoolAmount1, buyPoolAmount1)
	if err != nil {
		return 0, err
	}

	var sellPoolAmount2, buyPoolAmount2 uint64
	if poolPair2.Token1IDStr == common.PRVIDStr {
		sellPoolAmount2 = poolPair2.Token1PoolValue
		buyPoolAmount2 = poolPair2.Token2PoolValue
	} else {
		sellPoolAmount2 = poolPair2.Token2PoolValue
		buyPoolAmount2 = poolPair2.Token1PoolValue
	}


	return UniswapValue(expectPRV, sellPoolAmount2, buyPoolAmount2)
}

//Get the remote server to check price for trading things
func CheckPrice(tokenToSell, TokenToBuy string, sellAmount uint64) (uint64, error) {
	responseInBytes, err := rpc.ConvertPDEPrice(tokenToSell, TokenToBuy, sellAmount)
	if err != nil {
		return 0, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return 0, err
	}

	var convertedPrice []*rpc.ConvertedPrice
	err = json.Unmarshal(response.Result, &convertedPrice)
	if err != nil {
		return 0, err
	}

	if len(convertedPrice) == 0 {
		return 0, fmt.Errorf("no convertedPrice found")
	}

	return convertedPrice[0].Price, nil
}

//Get the remote server to check cross price for trading things
func CheckXPrice(tokenToSell, TokenToBuy string, sellAmount uint64) (uint64, error) {
	if tokenToSell == common.PRVIDStr || TokenToBuy == common.PRVIDStr {
		return CheckPrice(tokenToSell, TokenToBuy, sellAmount)
	}

	expectedPRV, err := CheckPrice(tokenToSell, common.PRVIDStr, sellAmount)
	if err != nil {
		return 0, err
	}

	return CheckPrice(common.PRVIDStr, TokenToBuy, expectedPRV)
}