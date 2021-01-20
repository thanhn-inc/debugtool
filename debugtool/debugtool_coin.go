package debugtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/privacy/coin"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/jsonresult"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/wallet"
	"math/big"
)

func GetOutputCoins(outCoinKey *rpc.OutCoinKey, tokenID string, height uint64) ([]jsonresult.ICoinInfo, []*big.Int, error) {
	b, err := rpc.GetListOutputCoinsByRPC(outCoinKey, tokenID, height)
	if err != nil {
		return nil, nil, err
	}

	return ParseCoinFromJsonResponse(b)
}

//CheckCoinsSpent checks if the provided serial numbers have been spent or not.
//
//Returned result in boolean list.
func CheckCoinsSpent(shardID byte, tokenID string, snList []string) ([]bool, error) {
	b, err := rpc.HasSerialNumberByRPC(shardID, tokenID, snList)
	if err != nil {
		return []bool{}, err
	}

	response, err := rpchandler.ParseResponse(b)
	if err != nil {
		return []bool{}, err
	}

	var tmp []bool
	err = json.Unmarshal(response.Result, &tmp)
	if err != nil {
		return []bool{}, err
	}

	if len(tmp) != len(snList) {
		return []bool{}, errors.New(fmt.Sprintf("Length of result and length of snList mismathc: len(Result) = %v, len(snList) = %v. Perhaps the shardID was wrong.", len(tmp), len(snList)))
	}

	return tmp, nil
}

//GetUnspentOutputCoins retrieves all unspent coins of a private key, without sending the private key to the remote full node.
func GetUnspentOutputCoins(privateKey, tokenID string, height uint64) ([]coin.PlainCoin, []*big.Int, error) {
	keyWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, nil, err
	}

	outCoinKey, err := NewOutCoinKeyFromPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	outCoinKey.SetReadonlyKey("") // call this if you do not want the remote full node to decrypt your coin

	listOutputCoins, _, err := GetOutputCoins(outCoinKey, tokenID, height)
	if err != nil {
		return nil, nil, err
	}

	//fmt.Printf("Number of output coins: %v\n", len(listOutputCoins))

	if len(listOutputCoins) == 0 {
		return nil, nil, nil
	}

	listDecryptedOutCoins, listKeyImages, err := GetListDecryptedCoins(privateKey, listOutputCoins)
	if err != nil {
		return nil, nil, err
	}

	shardID := common.GetShardIDFromLastByte(keyWallet.KeySet.PaymentAddress.Pk[len(keyWallet.KeySet.PaymentAddress.Pk)-1])
	checkSpentList, err := CheckCoinsSpent(shardID, tokenID, listKeyImages)
	if err != nil {
		return nil, nil, err
	}

	listUnspentOutputCoins := make([]coin.PlainCoin, 0)
	for i, decryptedCoin := range listDecryptedOutCoins {
		if !checkSpentList[i] {
			listUnspentOutputCoins = append(listUnspentOutputCoins, decryptedCoin)
		}
	}

	return listUnspentOutputCoins, nil, nil
}

//GetBalance retrieves balance of a private key without sending this private key to the remote full node.
func GetBalance(privateKey, tokenID string) (uint64, error) {
	unspentCoins, _, err := GetUnspentOutputCoins(privateKey, tokenID, 0)
	if err != nil {
		return 0, err
	}

	balance := uint64(0)
	for _, unspentCoin := range unspentCoins {
		balance += unspentCoin.GetValue()
	}

	return balance, nil
}