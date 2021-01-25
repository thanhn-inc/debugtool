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
	if version == -1 {//Try either one of the version, if possible
		encodedTx, txHash, err := CreateRawTokenTransactionVer1(txParam)
		if err != nil {
			encodedTx, txHash, err1 := CreateRawTokenTransactionVer2(txParam)
			if err1 != nil {
				return nil, "", errors.New(fmt.Sprintf("cannot create raw token transaction for either version: %v, %v", err, err1))
			}

			return encodedTx, txHash, nil
		}

		return encodedTx, txHash, nil
	} else if version == 2 {
		return CreateRawTokenTransactionVer2(txParam)
	} else {
		return CreateRawTokenTransactionVer1(txParam)
	}
}

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

	//Calculate the total transacted amount
	totalAmount := uint64(0)
	for _, amount := range txParam.amountList {
		totalAmount += amount
	}

	//Create list of payment infos
	var tokenReceivers []*privacy.PaymentInfo
	if txParam.txTokenType == utils.CustomTokenInit {
		uniqueReceiver := privacy.PaymentInfo{PaymentAddress: senderWallet.KeySet.PaymentAddress, Amount: totalAmount, Message: []byte{}}
		tokenReceivers = []*privacy.PaymentInfo{&uniqueReceiver}
	} else {
		tokenReceivers, err = CreatePaymentInfos(txParam.receiverList, txParam.amountList)
		if err != nil {
			return nil, "", err
		}
	}

	prvFee := DefaultPRVFee

	hasPrivacyToken := true
	hasPrivacyPRV := true
	if txParam.md != nil {
		hasPrivacyToken = false
		hasPrivacyPRV = false
	} else if txParam.txTokenType == utils.CustomTokenInit {
		hasPrivacyPRV = true
		hasPrivacyToken = false
	}

	//Init PRV fee param
	coinsPRVToSpend, kvargsPRV, err := InitParams(privateKey, common.PRVIDStr, prvFee, hasPrivacyPRV, 1)
	if err != nil {
		return nil, "", err
	}

	//End init PRV fee param

	//Init token param
	var coinsTokenToSpend []privacy.PlainCoin
	var kvargsToken map[string]interface{}
	if txParam.txTokenType != utils.CustomTokenInit {
		coinsTokenToSpend, kvargsToken, err = InitParams(privateKey, tokenIDStr, totalAmount, true, 1)
		if err != nil {
			return nil, "", err
		}
	}
	//End init token param

	//Create token param for transactions
	tokenParam := tx_generic.NewTokenParam(tokenIDStr, "", "",
			totalAmount, txParam.txTokenType, tokenReceivers, coinsTokenToSpend, false, 0, kvargsToken)

	txTokenParam := tx_generic.NewTxTokenParams(&senderWallet.KeySet.PrivateKey, []*privacy.PaymentInfo{}, coinsPRVToSpend, prvFee,
		tokenParam, txParam.md, hasPrivacyPRV, hasPrivacyToken, shardID, nil, kvargsPRV)

	tx := new(tx_ver1.TxToken)
	err = tx.Init(txTokenParam)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("init txtokenver1 error: %v", err))
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot marshal txtokenver1: %v", err))
	}

	fmt.Println("txtokenver 1 created", string(txBytes))

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

	//Calculate the total transacted amount
	totalAmount := uint64(0)
	for _, amount := range txParam.amountList {
		totalAmount += amount
	}

	//Create list of payment infos
	var tokenReceivers []*privacy.PaymentInfo
	if txParam.txTokenType == utils.CustomTokenInit {
		uniqueReceiver := privacy.PaymentInfo{PaymentAddress: senderWallet.KeySet.PaymentAddress, Amount: totalAmount, Message: []byte{}}
		tokenReceivers = []*privacy.PaymentInfo{&uniqueReceiver}
	} else {
		tokenReceivers, err = CreatePaymentInfos(txParam.receiverList, txParam.amountList)
		if err != nil {
			return nil, "", err
		}
	}

	prvFee := DefaultPRVFee

	//Init PRV fee param
	coinsToSpendPRV, kvargsPRV, err := InitParams(privateKey, common.PRVIDStr, prvFee, true, 2)
	if err != nil {
		return nil, "", err
	}
	//End init PRV fee param

	//Init token param
	var coinsTokenToSpend []privacy.PlainCoin
	var kvargsToken map[string]interface{}
	if txParam.txTokenType != utils.CustomTokenInit {
		coinsTokenToSpend, kvargsToken, err = InitParams(privateKey, tokenIDStr, totalAmount, true, 2)
		if err != nil {
			return nil, "", err
		}
	}
	//End init token param

	//Create token param for transactions
	tokenParam := tx_generic.NewTokenParam(tokenIDStr, "", "",
			totalAmount, txParam.txTokenType, tokenReceivers, coinsTokenToSpend, false, 0, kvargsToken)

	txTokenParam := tx_generic.NewTxTokenParams(&senderWallet.KeySet.PrivateKey, []*privacy.PaymentInfo{}, coinsToSpendPRV, prvFee,
		tokenParam, txParam.md, true, true, shardID, nil, kvargsPRV)

	tx := new(tx_ver2.TxToken)
	err = tx.Init(txTokenParam)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("init txtokenver1 error: %v", err))
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot marshal txtokenver1: %v", err))
	}

	fmt.Println("txtokenver 2 created", string(txBytes))

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

	//We need to use PRV coinV2 to payment (it's a must)
	prvFee := DefaultPRVFee
	coinsToSpendPRV, kvargsPRV, err := InitParams(privateKey, common.PRVIDStr, prvFee, true, 2)
	if err != nil {
		return nil, "", err
	}

	fmt.Println("Getting UTXOs for token...")
	//Get list of UTXOs
	utxoListToken, _, err := GetUnspentOutputCoins(privateKey, tokenIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs for token. Length of UTXOs: %v\n", len(utxoListToken))


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

	//Create unique receiver for token
	uniquePayment := privacy.PaymentInfo{PaymentAddress: senderWallet.KeySet.PaymentAddress, Amount: totalAmount, Message: []byte{}}

	txTokenParam := tx_ver2.NewTxTokenConvertVer1ToVer2InitParams(&(senderWallet.KeySet.PrivateKey), coinsToSpendPRV, []*privacy.PaymentInfo{}, coinV1ListToken,
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
	txParam := NewTxParam(privateKey, addrList, amountList, tokenIDStr, txTokenType, nil)

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
