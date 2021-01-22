package debugtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/metadata"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/transaction/tx_generic"
	"github.com/thanhn-inc/debugtool/transaction/tx_ver1"
	"github.com/thanhn-inc/debugtool/transaction/tx_ver2"
	"github.com/thanhn-inc/debugtool/transaction/utils"
	"github.com/thanhn-inc/debugtool/wallet"
)

func CreateRawTokenTransaction(privateKey string, addrList []string, amountList []uint64, version int8, tokenIDStr string, tokenType int, md metadata.Metadata) ([]byte, string, error) {
	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	lastByteSender := senderWallet.KeySet.PaymentAddress.Pk[len(senderWallet.KeySet.PaymentAddress.Pk)-1]
	shardID := common.GetShardIDFromLastByte(lastByteSender)

	//Create list of payment infos
	tokenReceivers, err := CreatePaymentInfos(addrList, amountList)
	if err != nil {
		return nil, "", err
	}

	//Calculate the total transacted amount
	totalAmount := uint64(0)
	for _, amount := range amountList {
		totalAmount += amount
	}

	prvFee := DefaultPRVFee

	fmt.Println("Getting UTXOs for paying fee...")
	//Get list of UTXOs
	utxoListPRV, _, err := GetUnspentOutputCoins(privateKey, common.PRVIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs for paying fee. Length of UTXOs: %v\n", len(utxoListPRV))

	fmt.Println("Getting UTXOs for token...")
	//Get list of UTXOs
	utxoListToken, _, err := GetUnspentOutputCoins(privateKey, tokenIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs for token. Length of UTXOs: %v\n", len(utxoListToken))

	coinV1ListPRV, _, _, err := DivideCoins(utxoListPRV, nil, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	coinV1ListToken, _, _, err := DivideCoins(utxoListToken, nil, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	if version == 1 {
		//Choose best coins for paying fee
		coinsToSpendPRV, _, err := ChooseBestCoinsByAmount(coinV1ListPRV, totalAmount)
		if err != nil {
			return nil, "", err
		}

		//Choose best token coins to spend
		coinsToSpendToken, _, err := ChooseBestCoinsByAmount(coinV1ListToken, totalAmount)
		if err != nil {
			return nil, "", err
		}

		fmt.Printf("Getting random commitments for prv.\n")
		//Retrieve commitments and indices
		kvargsPRV, err := GetRandomCommitments(coinsToSpendPRV, common.PRVIDStr)
		if err != nil {
			return nil, "", err
		}
		fmt.Printf("Finish getting random commitments for prv.\n")

		fmt.Printf("Getting random commitments for token.\n")
		//Retrieve commitments and indices
		kvargsToken, err := GetRandomCommitments(coinsToSpendToken, tokenIDStr)
		if err != nil {
			return nil, "", err
		}
		fmt.Printf("Finish getting random commitments for token.\n")

		tokenParam := tx_generic.NewTokenParam(tokenIDStr, "", "",
			totalAmount, tokenType, tokenReceivers, coinsToSpendToken, false, 0, kvargsToken)

		txTokenParam := tx_generic.NewTxTokenParams(&senderWallet.KeySet.PrivateKey, []*privacy.PaymentInfo{}, coinsToSpendPRV, prvFee,
			tokenParam, md, true, md == nil, shardID, nil, kvargsPRV)

		tx := new(tx_ver1.TxToken)
		err = tx.Init(txTokenParam)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("init txtokenver1 error: %v", err))
		}

		txBytes, err := json.Marshal(tx)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("cannot marshal txtokenver1: %v", err))
		}

		base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

		return []byte(base58CheckData), tx.Hash().String(), nil
	}

	return nil, "", nil
}

func CreateRawTokenConversionTransaction(privateKey, tokenID string) ([]byte, string, error) {
	if tokenID == common.PRVIDStr {
		return nil, "", errors.New("try conversion transaction")
	}

	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	fmt.Println("Getting UTXOs for paying fee...")
	//Get list of UTXOs
	utxoListPRV, _, err := GetUnspentOutputCoins(privateKey, common.PRVIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs for paying fee. Length of UTXOs: %v\n", len(utxoListPRV))

	fmt.Println("Getting UTXOs for token...")
	//Get list of UTXOs
	utxoListToken, _, err := GetUnspentOutputCoins(privateKey, tokenID, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs for token. Length of UTXOs: %v\n", len(utxoListToken))

	//We need to use PRV coinV2 to payment (it's a must)
	_, coinPRVV2List, idxPRVList, err := DivideCoins(utxoListPRV, nil, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	//Check if we have enough PRV to pay the tx fee
	prvFee := DefaultPRVFee
	totalPRVAmountV2 := uint64(0)
	for _, prvCoin := range coinPRVV2List {
		totalPRVAmountV2 += prvCoin.GetValue()
	}
	if totalPRVAmountV2 < prvFee {
		fmt.Printf("Total amount (%v) is less than txFee (%v).\n", totalPRVAmountV2, prvFee)
		return nil, "", errors.New(fmt.Sprintf("Total amount (%v) is less than txFee (%v).\n", totalPRVAmountV2, prvFee))
	}

	//We only need to convert token version 1
	coinV1ListToken, _, _, err := DivideCoins(utxoListToken, nil, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	//Calculate the total token amount to be converted
	totalAmount := uint64(0)
	for _, utxo := range coinV1ListToken {
		totalAmount += utxo.GetValue()
	}

	//==========Choose best PRV coins to pay the tx fee
	//Choose best coins to spend
	coinPRVsToSpend, chosenCoinIdxList, err := ChooseBestCoinsByAmount(coinPRVV2List, prvFee)
	if err != nil {
		return nil, "", err
	}

	var kvargsPRV map[string]interface{}
	fmt.Printf("Getting random commitments and public keys.\n")

	pkSender := senderWallet.KeySet.PaymentAddress.Pk
	shardID := common.GetShardIDFromLastByte(pkSender[len(pkSender)-1])

	lenDecoys := len(coinPRVsToSpend) * (privacy.RingSize - 1)

	//Retrieve commitments and indices
	kvargsPRV, err = GetRandomCommitmentsAndPublicKeys(shardID, common.PRVIDStr, lenDecoys)
	if err != nil {
		return nil, "", err
	}
	idxToSpendList := make([]uint64, 0)
	for _, idx := range chosenCoinIdxList {
		idxToSpendList = append(idxToSpendList, idxPRVList[idx])
	}
	kvargsPRV[utils.MyIndices] = idxToSpendList
	fmt.Printf("Finish getting random commitments and public keys.\n")

	//Create unique receiver for token
	uniquePayment := privacy.PaymentInfo{PaymentAddress: senderWallet.KeySet.PaymentAddress, Amount: totalAmount, Message: []byte{}}

	tokenParam := tx_generic.NewTokenParam(tokenID, "", "",
		totalAmount, 1, []*privacy.PaymentInfo{&uniquePayment}, coinV1ListToken, false, 0, nil)

	txTokenParam := tx_generic.NewTxTokenParams(&senderWallet.KeySet.PrivateKey, []*privacy.PaymentInfo{}, coinPRVsToSpend, prvFee,
		tokenParam, nil, true, false, shardID, nil, kvargsPRV)

	tx := new(tx_ver2.TxToken)
	err = tx.Init(txTokenParam)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("init txtokenconversion error: %v", err))
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot marshal txtokenconversion: %v", err))
	}

	base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

	return []byte(base58CheckData), tx.Hash().String(), nil

}

func CreateAndSendRawTokenTransaction(privateKey string, addrList []string, amountList []uint64, version int8, tokenIDStr string, txTokenType int) (string, error) {
	encodedTx, txHash, err := CreateRawTokenTransaction(privateKey, addrList, amountList, version, tokenIDStr, txTokenType, nil)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTokenTx(string(encodedTx))
	if err != nil {
		return "", nil
	}

	fmt.Println("SendRawTokenTx:", string(responseInBytes))

	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

func CreateAndSendRawTokenConversionTransaction(privateKey string, tokenID string) (string, error) {
	encodedTx, txHash, err := CreateRawTokenConversionTransaction(privateKey, tokenID)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTokenTx(string(encodedTx))
	if err != nil {
		return "", nil
	}

	fmt.Println("SendRawTx:", string(responseInBytes))

	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}
