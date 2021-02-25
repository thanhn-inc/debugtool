package debugtool

import (
	"encoding/json"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/jsonresult"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/wallet"
)

type CustomToken struct {
	tokenID   string
	tokenName string
	amount    uint64
}

func (ct CustomToken) ToString() string {
	return fmt.Sprintf("tokenID: %v, tokenName: %v, amount: %v", ct.tokenID, ct.tokenName, ct.tokenID)
}

func GetActiveShard() (int, error) {
	responseInBytes, err := rpc.GetActiveShards()
	if err != nil {
		return 0, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return 0, err
	}

	var activeShards int
	err = json.Unmarshal(response.Result, &activeShards)

	return activeShards, err
}

func GetBestBlock() (map[int]uint64, error) {
	responseInBytes, err := rpc.GetBestBlock()
	if err != nil {
		return nil, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return nil, err
	}

	var bestBlocksResult jsonresult.GetBestBlockResult
	err = json.Unmarshal(response.Result, &bestBlocksResult)
	if err != nil {
		return nil, err
	}

	res := make(map[int]uint64)

	for key, value := range bestBlocksResult.BestBlocks {
		res[key] = value.Height
	}

	return res, nil
}

func GetListToken() (map[string]CustomToken, error) {
	responseInBytes, err := rpc.ListPrivacyCustomTokenByRPC()
	if err != nil {
		return nil, err
	}
	var res rpc.ListCustomToken
	err = json.Unmarshal(responseInBytes, &res)
	if err != nil {
		return nil, err
	}

	tokenCount := 0
	listTokens := make(map[string]CustomToken)
	for _, token := range res.Result.ListCustomToken {
		tmp := CustomToken{
			tokenID:   token.ID,
			tokenName: token.Name,
			amount:    uint64(token.Amount),
		}
		if len(tmp.tokenName) == 0 {
			tmp.tokenName = string(tokenCount)
		}

		listTokens[token.ID] = tmp
		tokenCount++
	}

	return listTokens, nil
}

func GetRawMempool() ([]string, error) {
	responseInBytes, err := rpc.GetRawMempool()
	if err != nil {
		return nil, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return nil, err
	}

	var txHashes map[string][]string
	err = json.Unmarshal(response.Result, &txHashes)
	if err != nil {
		return nil, err
	}

	txList, ok := txHashes["TxHashes"]
	if !ok {
		return nil, fmt.Errorf("TxHashes not found in %v", txHashes)
	}

	return txList, nil

}

//Keys
func PrivateKeyToPaymentAddress(privkey string, keyType int) string {
	keyWallet, _ := wallet.Base58CheckDeserialize(privkey)
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	paymentAddStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	switch keyType {
	case 0: //Old address, old encoding
		addr, _ := wallet.GetPaymentAddressV1(paymentAddStr, false)
		return addr
	case 1:
		addr, _ := wallet.GetPaymentAddressV1(paymentAddStr, true)
		return addr
	default:
		return paymentAddStr
	}
}
func PrivateKeyToPublicKey(privkey string) []byte {
	keyWallet, err := wallet.Base58CheckDeserialize(privkey)
	if err != nil {
		return nil
	}
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	return keyWallet.KeySet.PaymentAddress.Pk
}
func PrivateKeyToPrivateOTAKey(privkey string) string {
	keyWallet, err := wallet.Base58CheckDeserialize(privkey)
	if err != nil {
		panic(err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	return keyWallet.Base58CheckSerialize(wallet.OTAKeyType)
}

func PrivateKeyToReadonlyKey(privkey string) string {
	keyWallet, err := wallet.Base58CheckDeserialize(privkey)
	if err != nil {
		panic(err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	return keyWallet.Base58CheckSerialize(wallet.ReadonlyKeyType)
}

func GetShardIDFromPrivateKey(privateKey string) byte {
	pubkey := PrivateKeyToPublicKey(privateKey)
	return common.GetShardIDFromLastByte(pubkey[len(pubkey)-1])
}