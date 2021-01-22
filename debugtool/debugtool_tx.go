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

func CreateRawTransaction(privateKey string, addrList []string, amountList []uint64, version int8, md metadata.Metadata) ([]byte, string, error) {
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
	utxoList, idxList, err := GetUnspentOutputCoins(privateKey, common.PRVIDStr, 0)
	if err != nil {
		return nil, "", err
	}

	fmt.Printf("Finish getting UTXOs. Length of UTXOs: %v\n", len(utxoList))

	coinV1List, coinV2List, idxV2List, err := DivideCoins(utxoList, idxList, true)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot divide coin: %v", err))
	}

	hasPrivacy := true
	if md != nil {
		hasPrivacy = false
	}

	if version == 1 {
		//Choose best coins to spend
		coinsToSpend, _, err := ChooseBestCoinsByAmount(coinV1List, totalAmount)
		if err != nil {
			return nil, "", err
		}

		var kvargs map[string]interface{}
		if hasPrivacy {
			fmt.Printf("Getting random commitments.\n")
			//Retrieve commitments and indices
			kvargs, err = GetRandomCommitments(coinsToSpend, common.PRVIDStr)
			if err != nil {
				return nil, "", err
			}
			fmt.Printf("Finish getting random commitments.\n")
		}

		txParam := tx_generic.NewTxPrivacyInitParams(&(senderWallet.KeySet.PrivateKey), paymentInfos, coinsToSpend, DefaultPRVFee, hasPrivacy, &common.PRVCoinID, md, nil, kvargs)

		tx := new(tx_ver1.Tx)
		err = tx.Init(txParam)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("init txver1 error: %v", err))
		}

		for _, inputCoin := range tx.GetProof().GetInputCoins() {
			fmt.Println("inputcoin:", inputCoin.GetCommitment().ToBytesS(), inputCoin.GetPublicKey().ToBytesS(),
				inputCoin.GetValue(), inputCoin.GetSNDerivator().ToBytesS(), inputCoin.GetRandomness().ToBytesS())
		}

		txBytes, err := json.Marshal(tx)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("cannot marshal txver1: %v", err))
		}

		fmt.Println("tx created", string(txBytes))

		base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

		return []byte(base58CheckData), tx.Hash().String(), nil
	} else {
		//Choose best coins to spend
		coinsToSpend, chosenCoinIdxList, err := ChooseBestCoinsByAmount(coinV2List, totalAmount)
		if err != nil {
			return nil, "", err
		}

		var kvargs map[string]interface{}
		fmt.Printf("Getting random commitments and public keys.\n")

		pkSender := senderWallet.KeySet.PaymentAddress.Pk
		shardID := common.GetShardIDFromLastByte(pkSender[len(pkSender)-1])

		lenDecoys := len(coinsToSpend) * (privacy.RingSize - 1)

		//Retrieve commitments and indices
		kvargs, err = GetRandomCommitmentsAndPublicKeys(shardID, common.PRVIDStr, lenDecoys)
		if err != nil {
			return nil, "", err
		}
		idxToSpendList := make([]uint64, 0)
		for _, idx := range chosenCoinIdxList {
			idxToSpendList = append(idxToSpendList, idxV2List[idx])
		}
		kvargs[utils.MyIndices] = idxToSpendList
		fmt.Printf("Finish getting random commitments and public keys.\n")

		txParam := tx_generic.NewTxPrivacyInitParams(&(senderWallet.KeySet.PrivateKey), paymentInfos, coinsToSpend, DefaultPRVFee, hasPrivacy, &common.PRVCoinID, md, nil, kvargs)

		tx := new(tx_ver2.Tx)
		err = tx.Init(txParam)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("init txver1 error: %v", err))
		}

		txBytes, err := json.Marshal(tx)
		if err != nil {
			return nil, "", errors.New(fmt.Sprintf("cannot marshal txver1: %v", err))
		}

		fmt.Println("tx created", string(txBytes))

		base58CheckData := base58.Base58Check{}.Encode(txBytes, common.ZeroByte)

		return []byte(base58CheckData), tx.Hash().String(), nil
	}
}

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

func CreateAndSendRawTransaction(privateKey string, addrList []string, amountList []uint64, version int8, md metadata.Metadata) (string, error) {
	encodedTx, txHash, err := CreateRawTransaction(privateKey, addrList, amountList, version, md)
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

//func CheckTransactionStatus(txHash string) ([]bool, error) {
//
//}
