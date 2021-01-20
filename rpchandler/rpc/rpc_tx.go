package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/wallet"
)
//========== GET RPCs ==========

// Query the RPC server then return the AutoTxByHash
func getAutoTxByHash(txHash string) (*AutoTxByHash, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return nil, errors.New("Server has not set mainnet or testnet")
	}
	query := fmt.Sprintf(`{
		"jsonrpc":"1.0",
		"method":"gettransactionbyhash",
		"params":["%s"],
		"id":1
	}`, txHash)
	b, err := rpchandler.Server.SendPostRequestWithQuery(query)
	if err != nil {
		return nil, err
	}
	autoTx, txError := ParseAutoTxHashFromBytes(b)
	if txError != nil {
		return nil, err
	}
	return autoTx, nil
}

// Get only the proof of transaction requiring the txHash
func GetProofTransactionByHash(txHash string) (string, error) {
	tx, err := getAutoTxByHash(txHash)
	if err != nil {
		return "", err
	}
	return tx.Result.Proof, nil
}

// Get only the Sig of transaction requiring the txHash
func GetSigTransactionByHash(txHash string) (string, error) {
	tx, err := getAutoTxByHash(txHash)
	if err != nil {
		return "", err
	}
	return tx.Result.Sig, nil
}

// Get only the BlockHash of transaction requiring the txHash
func GetBlockHashTransactionByHash(txHash string) (string, error) {
	tx, err := getAutoTxByHash(txHash)
	if err != nil {
		return "", err
	}
	return tx.Result.BlockHash, nil
}

// Get only the BlockHeight of transaction requiring the txHash
func GetBlockHeightTransactionByHash(txHash string) (int, error) {
	tx, err := getAutoTxByHash(txHash)
	if err != nil {
		return -1, err
	}
	return tx.Result.BlockHeight, nil
}

// Get the whole result of rpc call 'gettransactionbyhash'
func GetTransactionByHash(txHash string) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	query := fmt.Sprintf(`{
		"jsonrpc":"1.0",
		"method":"gettransactionbyhash",
		"params":["%s"],
		"id":1
	}`, txHash)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

//========== END GET RPCs ==========

//========== CREATE TX RPCs ==========

func CreateAndSendTransaction() ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc": "1.0",
		"method": "createandsendtransaction",
		"params": [
			"112t8roafGgHL1rhAP9632Yef3sx5k8xgp8cwK4MCJsCL1UWcxXvpzg97N4dwvcD735iKf31Q2ZgrAvKfVjeSUEvnzKJyyJD3GqqSZdxN4or",
			{
				"12RuhVZQtGgYmCVzVi49zFZD7gR8SQx8Uuz8oHh6eSZ8PwB2MwaNE6Kkhd6GoykfkRnHNSHz1o2CzMiQBCyFPikHmjvvrZkLERuhcVE":200000000000000,
				"12RxDSnQVjPojzf7uju6dcgC2zkKkg85muvQh347S76wKSSsKPAqXkvfpSeJzyEH3PREHZZ6SKsXLkDZbs3BSqwEdxqprqih4VzANK9":200000000000000,
				"12S6m2LpzN17jorYnLb2ApNKaV2EVeZtd6unvrPT1GH8yHGCyjYzKbywweQDZ7aAkhD31gutYAgfQizb2JhJTgBb3AJ8aB4hyppm2ax":200000000000000,
				"12S42y9fq8xWXx1YpZ6KVDLGx6tLjeFWqbSBo6zGxwgVnPe1rMGxtLs87PyziCzYPEiRGdmwU1ewWFXwjLwog3X71K87ApNUrd3LQB3":200000000000000,
				"12S3yvTvWUJfubx3whjYLv23NtaNSwQMGWWScSaAkf3uQg8xdZjPFD4fG8vGvXjpRgrRioS5zuyzZbkac44rjBfs7mEdgoL4pwKu87u":200000000000000,
				"12S6mGbnS3Df5bGBaUfBTh56NRax4PvFPDhUnxvP9D6cZVjnTx9T4FsVdFT44pFE8KXTGYaHSAmb2MkpnUJzkrAe49EPHkBULM8N2ZJ":200000000000000,
				"12Rs5tQTYkWGzEdPNo2GRA1tjZ5aDCTYUyzXf6SJFq89QnY3US3ZzYSjWHVmmLUa6h8bdHHUuVYoR3iCVRoYDCNn1AfP6pxTz5YL8Aj":200000000000000,
				"12S33dTF3aVsuSxY7iniK3UULUYyLMZumExKm6DPfsqnNepGjgDZqkQCDp1Z7Te9dFKQp7G2WeeYqCr5vcDCfrA3id4x5UvL4yyLrrT":200000000000000
			},
			1,
			1
		],
		"id": 1
	}`
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func CreateAndSendTransactionFromAToB(privKeyA string, paymentAddress string, amount string) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}

	query := fmt.Sprintf(`{
		"jsonrpc": "1.0",
		"method": "createandsendtransaction",
		"params": [
			"%s",
			{
				"%s": %s
			},
			1,
			%s
		],
		"id": 1
	}`, privKeyA, paymentAddress, amount, privIndicator)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func CreateAndSendPrivacyCustomTokenTransaction(privKeyStr, tokenName string) ([]byte, error) {
	keyWallet, _ := wallet.Base58CheckDeserialize(privKeyStr)
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	paymentAddStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	query := fmt.Sprintf(`{
		"id": 1,
		"jsonrpc": "1.0",
		"method": "createandsendprivacycustomtokentransaction",
		"params": [
			"%s",
			{},
			5,
			1,
			{
				"Privacy": true,
				"TokenID": "",
				"TokenName": "%s",
				"TokenSymbol": "pTTT",
				"TokenFee": 0,
				"TokenTxType": 0,
				"TokenAmount": 1000000000000000000,
				"TokenReceivers": {
					"%s": 1000000000000000000
				}
			}
			]
	}`, privKeyStr, tokenName, paymentAddStr)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func TransferPrivacyCustomToken(privKeyStrA string, paymentAddress string, tokenID string, amount string) ([]byte, error) {

	query := fmt.Sprintf(`{
		"id": 1,
		"jsonrpc": "1.0",
		"method": "createandsendprivacycustomtokentransaction",
		"params": [
			"%s",
			null,
			10,
			1,
			{
				"Privacy": true,
				"TokenID": "%s",
				"TokenName": "",
				"TokenSymbol": "",
				"TokenFee": 0,
				"TokenTxType": 1,
				"TokenAmount": 0,
				"TokenReceivers": {
					"%s": %s
				}
			}
			]
	}`, privKeyStrA, tokenID, paymentAddress, amount)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func GetBalancePrivacyCustomToken(privKeyStr string, tokenID string) ([]byte, error) {
	query := fmt.Sprintf(`{
		"id": 1,
		"jsonrpc": "1.0",
		"method": "getbalanceprivacycustomtoken",
		"params": [
			"%s",
			"%s"
		]
	}`, privKeyStr, tokenID)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func SwitchTokenCoinVersion(privKey string, tokenID string) ([]byte, error) {
	query := fmt.Sprintf(`{
		"jsonrpc": "1.0",
		"method": "createconvertcoinver1tover2txtoken",
		"params": [
			"%s",
			"%s",
			1
		],
		"id": 1
	}`, privKey, tokenID)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func SwitchCoinVersion(privKey string) ([]byte, error) {
	query := fmt.Sprintf(`{
		"jsonrpc": "1.0",
		"method": "createconvertcoinver1tover2transaction",
		"params": [
			"%s",
			1
		],
		"id": 1
	}`, privKey)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

//========== END CREATE TX RPCs ==========

func SendRawTx(encodedTx string) ([]byte, error) {
	method := "sendtransaction"
	params := make([]interface{}, 0)
	params = append(params, encodedTx)

	request := rpchandler.CreateJsonRequest("1.0", method, params, 1)
	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.Server.SendPostRequestWithQuery(string(query))
}

