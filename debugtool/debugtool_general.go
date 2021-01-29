package debugtool

import (
	"encoding/json"
	"fmt"
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
	response, err := rpc.ListPrivacyCustomTokenByRPC()
	if err != nil {
		return nil, err
	}
	res := new(rpc.ListCustomToken)
	err = json.Unmarshal(response, res)
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
		panic(err)
	}
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	return keyWallet.KeySet.PaymentAddress.Pk
}