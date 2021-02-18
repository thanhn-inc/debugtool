package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/jsonresult"
	"github.com/thanhn-inc/debugtool/wallet"
)



//===================== OUTPUT COINS RPC =====================//
//These RPCs return raw JSON bytes.

//GetListOutputCoinsByRPC retrieves list of output coins of an OutCoinKey and returns the result in raw json bytes.
func GetListOutputCoinsByRPC(outCoinKey *OutCoinKey, tokenID string, h uint64) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}

	query := fmt.Sprintf(`{
		"jsonrpc": "1.0",
		"method": "listoutputcoins",
		"params": [
			0,
			999999,
			[
				{
			  "PaymentAddress": "%s",
			  "OTASecretKey": "%s",
			  "ReadonlyKey" : "%s",
			  "StartHeight": %d
				}
			],
		  "%s"
		  ],
		"id": 1
	}`, outCoinKey.paymentAddress, outCoinKey.otaKey, outCoinKey.readonlyKey, h, tokenID)

	return rpchandler.Server.SendPostRequestWithQuery(query)
}

//GetListOutputCoinsCachedByRPC retrieves list of output coins (which have been cached at the fullnode) of an OutCoinKey and returns the result in raw json bytes.
func GetListOutputCoinsCachedByRPC(privKeyStr, tokenID string, h uint64) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}

	keyWallet, _ := wallet.Base58CheckDeserialize(privKeyStr)
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	paymentAddStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	otaSecretKey := keyWallet.Base58CheckSerialize(wallet.OTAKeyType)
	viewingKeyStr := keyWallet.Base58CheckSerialize(wallet.ReadonlyKeyType)

	query := fmt.Sprintf(`{
		"jsonrpc": "1.0",
		"method": "listoutputcoinsfromcache",
		"params": [
			0,
			999999,
			[
				{
			  "PaymentAddress": "%s",
			  "OTASecretKey": "%s",
			  "ReadonlyKey" : "%s",
			  "StartHeight": %d
				}
			],
		  "%s"
		  ],
		"id": 1
	}`, paymentAddStr, otaSecretKey, viewingKeyStr, h, tokenID)

	//fmt.Println("==============")

	return rpchandler.Server.SendPostRequestWithQuery(query)
}

//ListUnspentOutputCoinsByRPC retrieves list of output coins of an OutCoinKey and returns the result in raw json bytes.
//
//NOTE: PrivateKey must be supplied.
func ListUnspentOutputCoinsByRPC(privKeyStr string) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}

	query := fmt.Sprintf(`{
	   "jsonrpc":"1.0",
	   "method":"listunspentoutputcoins",
	   "params":[
		  0,
		  999999,
		  [
			 {
				"PrivateKey":"%s",
				"StartHeight": 0
			 }

		  ]
	   ],
	   "id":1
	}`, privKeyStr)

	return rpchandler.Server.SendPostRequestWithQuery(query)
}

//ListPrivacyCustomTokenByRPC lists all tokens currently present on the blockchain
func ListPrivacyCustomTokenByRPC() ([]byte, error) {
	query := `{
		"id": 1,
		"jsonrpc": "1.0",
		"method": "listprivacycustomtoken",
		"params": []
	}`
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

//ListPrivacyCustomTokenByRPC lists all tokens currently present on the blockchain
func ListBridgeTokenByRPC() ([]byte, error) {
	method := getAllBridgeTokens

	params := make([]interface{}, 0)

	request := rpchandler.CreateJsonRequest("1.0", method, params, 1)

	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.Server.SendPostRequestWithQuery(string(query))
}

//HasSerialNumberByRPC checks if the provided serial numbers have been spent or not.
//
//Returned result in raw json bytes.
func HasSerialNumberByRPC(shardID byte, tokenID string, snList []string) ([]byte, error) {
	if len(snList) == 0 {
		return nil, errors.New("no serial number provided to be checked")
	}
	snQueryList := make([]string, 0)
	for _, sn := range snList {
		snQueryList = append(snQueryList, fmt.Sprintf(`"%s"`, sn))
	}

	addr := rpchandler.CreatePaymentAddress(shardID)

	method := hasSerialNumbers

	params := make([]interface{}, 0)
	params = append(params, addr)
	params = append(params, snList)
	params = append(params, tokenID)

	request := rpchandler.CreateJsonRequest("1.0", method, params, 1)

	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.Server.SendPostRequestWithQuery(string(query))

}

func GetBalanceByPrivatekey(privKeyStr string) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}

	query := fmt.Sprintf(`{
	   "jsonrpc":"1.0",
	   "method":"getbalancebyprivatekey",
	   "params":["%s"],
	   "id":1
	}`, privKeyStr)

	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func SubmitKey(otaStr string) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}

	keyWallet, err := wallet.Base58CheckDeserialize(otaStr)
	if err != nil {
		return nil, err
	}

	rawOTA := make([]byte, 0)
	rawOTA = append(rawOTA, keyWallet.KeySet.OTAKey.GetOTASecretKey().ToBytesS()...)
	rawOTA = append(rawOTA, keyWallet.KeySet.OTAKey.GetPublicSpend().ToBytesS()...)

	otaToBeSent := hex.EncodeToString(rawOTA)

	query := fmt.Sprintf(`{
	   "jsonrpc":"1.0",
	   "method":"submitkey",
	   "params":["%s"],
	   "id":1
	}`, otaToBeSent)

	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func RandomCommitments (shardID byte, inputCoins []jsonresult.OutCoin, tokenID string) ([]byte, error) {
	addr := rpchandler.CreatePaymentAddress(shardID)

	method := randomCommitments

	params := make([]interface{}, 0)
	params = append(params, addr)
	params = append(params, inputCoins)
	params = append(params, tokenID)

	request := rpchandler.CreateJsonRequest("1.0", method, params, 1)

	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.Server.SendPostRequestWithQuery(string(query))
}

func RandomCommitmentsAndPublicKeys (shardID byte, tokenID string, lenDecoy int) ([]byte, error) {
	method := randomCommitmentsAndPublicKeys

	params := make([]interface{}, 0)
	params = append(params, shardID)
	params = append(params, lenDecoy)
	params = append(params, tokenID)

	request := rpchandler.CreateJsonRequest("1.0", method, params, 1)

	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.Server.SendPostRequestWithQuery(string(query))
}
//===================== END OF OUTPUT COINS RPC =====================//
