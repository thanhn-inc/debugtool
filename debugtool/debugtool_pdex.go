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

func CreatePDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	pdeTradeMetadata, err := metadata.NewPDETradeRequest(tokenIDToBuy, tokenIDToSell, amount, 0, 0,
		addr, "", metadata.PDETradeRequestMeta)

	txParam := NewTxParam(privateKey, []string{common.BurningAddress2}, []uint64{amount}, common.PRVIDStr, 0, pdeTradeMetadata)

	return CreateRawTransaction(txParam, -1)
}
func CreateAndSendPDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64) (string, error) {
	encodedTx, txHash, err := CreatePDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy, amount)
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