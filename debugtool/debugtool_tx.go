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
	"github.com/thanhn-inc/debugtool/rpchandler/jsonresult"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/transaction/tx_generic"
	"github.com/thanhn-inc/debugtool/transaction/tx_ver1"
	"github.com/thanhn-inc/debugtool/transaction/tx_ver2"
	"github.com/thanhn-inc/debugtool/wallet"
)

func CreateRawTransaction(param *TxParam, version int8) ([]byte, string, error) {
	if version == -1 {//Try either one of the version, if possible
		encodedTx, txHash, err := CreateRawTransactionVer1(param)
		if err != nil {
			encodedTx, txHash, err1 := CreateRawTransactionVer2(param)
			if err1 != nil {
				return nil, "", errors.New(fmt.Sprintf("cannot create raw transaction for either version: %v, %v", err, err1))
			}

			return encodedTx, txHash, nil
		}

		return encodedTx, txHash, nil
	} else if version == 2 {
		return CreateRawTransactionVer2(param)
	} else {
		return CreateRawTransactionVer1(param)
	}
}

func CreateRawTransactionVer1(param *TxParam) ([]byte, string, error) {
	privateKey := param.senderPrivateKey
	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	//Create list of payment infos
	paymentInfos, err := CreatePaymentInfos(param.receiverList, param.amountList)
	if err != nil {
		return nil, "", err
	}

	//Calculate the total transacted amount
	totalAmount := DefaultPRVFee
	for _, amount := range param.amountList {
		totalAmount += amount
	}

	hasPrivacy := true
	if param.md != nil {
		hasPrivacy = false
	}

	coinsToSpend, kvargs, err := InitParams(privateKey, common.PRVIDStr, totalAmount, hasPrivacy, 1)

	txInitParam := tx_generic.NewTxPrivacyInitParams(&(senderWallet.KeySet.PrivateKey), paymentInfos, coinsToSpend, DefaultPRVFee, hasPrivacy, &common.PRVCoinID, param.md, nil, kvargs)

	tx := new(tx_ver1.Tx)
	err = tx.Init(txInitParam)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("init txver1 error: %v", err))
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot marshal txver1: %v", err))
	}

	fmt.Println("txver 1 created", string(txBytes))

	base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

	return []byte(base58CheckData), tx.Hash().String(), nil
}

func CreateRawTransactionVer2(param *TxParam) ([]byte, string, error) {
	privateKey := param.senderPrivateKey
	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	//Create list of payment infos
	paymentInfos, err := CreatePaymentInfos(param.receiverList, param.amountList)
	if err != nil {
		return nil, "", err
	}

	//Calculate the total transacted amount
	totalAmount := DefaultPRVFee
	for _, amount := range param.amountList {
		totalAmount += amount
	}


	hasPrivacy := true
	if param.md != nil {
		hasPrivacy = false
	}

	coinsToSpend, kvargs, err := InitParams(privateKey, common.PRVIDStr, totalAmount, hasPrivacy, 2)

	txParam := tx_generic.NewTxPrivacyInitParams(&(senderWallet.KeySet.PrivateKey), paymentInfos, coinsToSpend, DefaultPRVFee, hasPrivacy, &common.PRVCoinID, param.md, nil, kvargs)

	tx := new(tx_ver2.Tx)
	err = tx.Init(txParam)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("init txver2 error: %v", err))
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot marshal txver2: %v", err))
	}

	fmt.Println("txver 2 created", string(txBytes))

	base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

	return []byte(base58CheckData), tx.Hash().String(), nil
}

func CreateRawConversionTransaction(privateKey string) ([]byte, string, error) {
	//Create sender private key from string
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init private key %v: %v", privateKey, err))
	}

	fmt.Println("Getting UTXOs")
	//Get list of UTXOs
	utxoList, _, err := GetUnspentOutputCoins(privateKey, common.PRVIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs. Length of UTXOs: %v\n", len(utxoList))

	//Get list of coinv1 to convert.
	coinV1List, _, _, err := DivideCoins(utxoList, nil, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	if len(coinV1List) == 0 {
		return nil, "", errors.New("no CoinV1 left to be converted")
	}

	//Calculating the total amount being converted.
	totalAmount := uint64(0)
	for _, utxo := range coinV1List {
		totalAmount += utxo.GetValue()
	}
	if totalAmount < DefaultPRVFee {
		fmt.Printf("Total amount (%v) is less than txFee (%v).\n", totalAmount, DefaultPRVFee)
		return nil, "", errors.New(fmt.Sprintf("Total amount (%v) is less than txFee (%v).\n", totalAmount, DefaultPRVFee))
	}
	totalAmount -= DefaultPRVFee

	uniquePayment := privacy.PaymentInfo{PaymentAddress: senderWallet.KeySet.PaymentAddress, Amount: totalAmount, Message: []byte{}}

	//Create tx conversion params
	txParam := tx_ver2.NewTxConvertVer1ToVer2InitParams(&(senderWallet.KeySet.PrivateKey), []*privacy.PaymentInfo{&uniquePayment}, coinV1List,
		DefaultPRVFee, nil, nil, nil, nil)

	tx := new(tx_ver2.Tx)
	err = tx_ver2.InitConversion(tx, txParam)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("init txconvert error: %v", err))
	}

	for _, inputCoin := range tx.GetProof().GetInputCoins() {
		fmt.Println("inputcoin:", inputCoin.GetCommitment().ToBytesS(), inputCoin.GetPublicKey().ToBytesS(),
			inputCoin.GetValue(), inputCoin.GetSNDerivator().ToBytesS(), inputCoin.GetRandomness().ToBytesS())
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot marshal txconvert: %v", err))
	}

	fmt.Println("tx created", string(txBytes))

	base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

	return []byte(base58CheckData), tx.Hash().String(), nil
}

func CreateAndSendRawTransaction(privateKey string, addrList []string, amountList []uint64, version int8, md metadata.Metadata) (string, error) {
	txParam := NewTxParam(privateKey, addrList, amountList, common.PRVIDStr, 0, md)
	encodedTx, txHash, err := CreateRawTransaction(txParam, version)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTx(string(encodedTx))
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

func CreateAndSendRawConversionTransaction(privateKey string) (string, error) {
	encodedTx, txHash, err := CreateRawConversionTransaction(privateKey)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTx(string(encodedTx))
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

func CheckTxInBlock(txHash string) (bool, error) {
	responseInBytes, err := rpc.GetTransactionByHash(txHash)
	if err != nil {
		return false, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return false, err
	}

	var txDetail jsonresult.TransactionDetail
	err = json.Unmarshal(response.Result, &txDetail)
	if err != nil {
		return false, err
	}

	if txDetail.IsInMempool {
		fmt.Printf("tx %v is currently in mempool\n", txHash)
		return false, nil
	}

	return txDetail.IsInBlock, nil
}
