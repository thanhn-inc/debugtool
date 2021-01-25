package debugtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/transaction/tx_generic"
	"github.com/thanhn-inc/debugtool/transaction/tx_ver1"
	"github.com/thanhn-inc/debugtool/transaction/tx_ver2"
	"github.com/thanhn-inc/debugtool/transaction/utils"
	"github.com/thanhn-inc/debugtool/wallet"
)

func CreateRawTokenTransaction(txParam *TxParam, version int8) ([]byte, string, error) {
	if version == 2 {
		return CreateRawTokenTransactionVer2(txParam)
	} else {
		return CreateRawTokenTransactionVer1(txParam)
	}
}

//Default transaction is hasPrivacy.
func CreateRawTokenTransactionVer1(txParam *TxParam) ([]byte, string, error) {
	privateKey := txParam.senderPrivateKey

	tokenIDStr := txParam.tokenID
	_, err := new(common.Hash).NewHashFromStr(tokenIDStr)
	if err != nil {
		return nil, "", err
	}
	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	lastByteSender := senderWallet.KeySet.PaymentAddress.Pk[len(senderWallet.KeySet.PaymentAddress.Pk)-1]
	shardID := common.GetShardIDFromLastByte(lastByteSender)

	//Create list of payment infos
	tokenReceivers, err := CreatePaymentInfos(txParam.receiverList, txParam.amountList)
	if err != nil {
		return nil, "", err
	}

	//Calculate the total transacted amount
	totalAmount := uint64(0)
	for _, amount := range txParam.amountList {
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
	utxoListToken, _, err := GetUnspentOutputCoins(privateKey, txParam.tokenID, 0)
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
		totalAmount, 1, tokenReceivers, coinsToSpendToken, false, 0, kvargsToken)

	txTokenParam := tx_generic.NewTxTokenParams(&senderWallet.KeySet.PrivateKey, []*privacy.PaymentInfo{}, coinsToSpendPRV, prvFee,
		tokenParam, txParam.md, true, txParam.md == nil, shardID, nil, kvargsPRV)

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

func CreateRawTokenTransactionVer2(txParam *TxParam) ([]byte, string, error) {
	privateKey := txParam.senderPrivateKey

	tokenIDStr := txParam.tokenID
	_, err := new(common.Hash).NewHashFromStr(tokenIDStr)
	if err != nil {
		return nil, "", err
	}
	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	lastByteSender := senderWallet.KeySet.PaymentAddress.Pk[len(senderWallet.KeySet.PaymentAddress.Pk)-1]
	shardID := common.GetShardIDFromLastByte(lastByteSender)

	//Create list of payment infos
	tokenReceivers, err := CreatePaymentInfos(txParam.receiverList, txParam.amountList)
	if err != nil {
		return nil, "", err
	}

	//Calculate the total transacted amount
	totalAmount := uint64(0)
	for _, amount := range txParam.amountList {
		totalAmount += amount
	}

	prvFee := DefaultPRVFee

	fmt.Println("Getting UTXOs for paying fee...")
	//Get list of UTXOs
	utxoListPRV, idxListPRV, err := GetUnspentOutputCoins(privateKey, common.PRVIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs for paying fee. Length of UTXOs: %v\n", len(utxoListPRV))

	fmt.Println("Getting UTXOs for token...")
	//Get list of UTXOs
	utxoListToken, idxList, err := GetUnspentOutputCoins(privateKey, txParam.tokenID, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs for token. Length of UTXOs: %v\n", len(utxoListToken))


	//=============CHOOSE COIN PRV V2 TO SPEND====================
	_, coinV2ListPRV, idxV2ListPRV, err := DivideCoins(utxoListPRV, idxListPRV, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	//=============CHOOSE COIN TOKEN V2 TO SPEND====================
	_, coinV2ListToken, idxV2ListToken, err := DivideCoins(utxoListToken, idxList, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	//Choose best coins for paying fee
	coinsToSpendPRV, chosenIdxPRV, err := ChooseBestCoinsByAmount(coinV2ListPRV, totalAmount)
	if err != nil {
		return nil, "", err
	}

	//Choose best token coins to spend
	coinsToSpendToken, chosenIdxToken, err := ChooseBestCoinsByAmount(coinV2ListToken, totalAmount)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Getting random commitments for prv.\n")
	//Retrieve commitments and indices
	kvargsPRV, err := GetRandomCommitmentsAndPublicKeys(shardID, common.PRVIDStr, len(coinsToSpendPRV) * (privacy.RingSize - 1))
	if err != nil {
		return nil, "", err
	}
	fmt.Printf("Finish getting random commitments for prv.\n")
	idxToSpendPRV := make([]uint64, 0)
	for _, idx := range chosenIdxPRV {
		idxToSpendPRV = append(idxToSpendPRV, idxV2ListPRV[idx])
	}
	kvargsPRV[utils.MyIndices] = idxToSpendPRV


	fmt.Printf("Getting random commitments for token.\n")
	//Retrieve commitments and indices
	kvargsToken, err := GetRandomCommitmentsAndPublicKeys(shardID, tokenIDStr, len(coinsToSpendToken) * (privacy.RingSize - 1))
	if err != nil {
		return nil, "", err
	}
	fmt.Printf("Finish getting random commitments for token.\n")
	idxToSpendToken := make([]uint64, 0)
	for _, idx := range chosenIdxToken {
		idxToSpendToken = append(idxToSpendToken, idxV2ListToken[idx])
	}
	kvargsToken[utils.MyIndices] = idxToSpendToken


	//Always paying fee by PRV
	tokenParam := tx_generic.NewTokenParam(tokenIDStr, "", "",
		totalAmount, 1, tokenReceivers, coinsToSpendToken, false, 0, kvargsToken)

	txTokenParam := tx_generic.NewTxTokenParams(&senderWallet.KeySet.PrivateKey, []*privacy.PaymentInfo{}, coinsToSpendPRV, prvFee,
		tokenParam, txParam.md, true, txParam.md == nil, shardID, nil, kvargsPRV)

	tx := new(tx_ver2.TxToken)
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

func CreateRawTokenConversionTransaction(privateKey, tokenIDStr string) ([]byte, string, error) {
	if tokenIDStr == common.PRVIDStr {
		return nil, "", errors.New("try conversion transaction")
	}

	tokenID, err := new(common.Hash).NewHashFromStr(tokenIDStr)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("invalid token ID: %v", tokenIDStr))
	}

	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	fmt.Println("Getting UTXOs for paying fee...")
	//Get list of UTXOs
	utxoListPRV, idxList, err := GetUnspentOutputCoins(privateKey, common.PRVIDStr, 0)
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

	//We need to use PRV coinV2 to payment (it's a must)
	_, coinPRVV2List, idxPRVList, err := DivideCoins(utxoListPRV, idxList, true)
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

	txTokenParam := tx_ver2.NewTxTokenConvertVer1ToVer2InitParams(&(senderWallet.KeySet.PrivateKey), coinPRVsToSpend, []*privacy.PaymentInfo{}, coinV1ListToken,
		[]*privacy.PaymentInfo{&uniquePayment}, prvFee, tokenID,
		nil, nil, kvargsPRV)

	tx := new(tx_ver2.TxToken)
	err = tx_ver2.InitTokenConversion(tx, txTokenParam)
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
	txParam := NewTxParam(privateKey, addrList, amountList, tokenIDStr, nil)

	encodedTx, txHash, err := CreateRawTokenTransaction(txParam, version)
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
