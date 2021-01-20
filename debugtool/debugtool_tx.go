package debugtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/LampardNguyen234/incognito-wallet/debugtool"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/transaction/tx_generic"
	"github.com/thanhn-inc/debugtool/transaction/tx_ver1"
	"github.com/thanhn-inc/debugtool/wallet"
)

func CreateRawTransaction(privateKey string, addrList []string, amountList []uint64, version int8) ([]byte, string, error) {
	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	//Create list of payment infos
	paymentInfos, err := CreatePaymentInfos(addrList, amountList)
	if err != nil {
		return nil, "", err
	}

	//Calculate the total transacted amount
	totalAmount := DefaultPRVFee
	for _, amount := range amountList {
		totalAmount += amount
	}

	fmt.Println("Getting UTXOs")
	//Get list of UTXOs
	utxoList, _, err := GetUnspentOutputCoins(privateKey, common.PRVIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs. Length of UTXOs: %v\n", len(utxoList))

	coinV1List, _, err := DivideCoins(utxoList, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	if version == 1 {
		//Choose best coins to spend
		coinsToSpend, err := ChooseBestCoinsByAmount(coinV1List, totalAmount)
		if err != nil {
			return nil, "", err
		}

		fmt.Printf("Getting random commitments.\n")
		//Retrieve commitments and indices
		kvargs, err := GetRandomCommitments(coinsToSpend, common.PRVIDStr)
		if err != nil {
			return nil, "", err
		}
		fmt.Printf("Finish getting random commitments.\n")

		txParam := tx_generic.NewTxPrivacyInitParams(&(senderWallet.KeySet.PrivateKey), paymentInfos, coinsToSpend, DefaultPRVFee, true, &common.PRVCoinID, nil, nil, kvargs)

		tx := new(tx_ver1.Tx)
		err = tx.Init(txParam)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("init txver1 error: %v", err))
		}

		txBytes, err := json.Marshal(tx)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("cannot marshal txver1: %v", err))
		}

		base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

		return []byte(base58CheckData), tx.Hash().String(), nil
	}

	return nil, "", nil
}

func CreateAndSendRawTransaction(privateKey string, addrList []string, amountList []uint64, version int8) (string, error) {
	encodedTx, txHash, err := CreateRawTransaction(privateKey, addrList, amountList, version)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTx(string(encodedTx))
	if err != nil {
		return "", nil
	}

	fmt.Println("SendRawTx:", string(responseInBytes))

	_, err = debugtool.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

//func CheckTransactionStatus(txHash string) ([]bool, error) {
//
//}