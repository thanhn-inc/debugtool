package debugtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/wallet"
)

var privIndicator string = "1"

// Parse from byte to AutoTxByHash
func ParseAutoTxHashFromBytes(b []byte) (*AutoTxByHash, error) {
	data := new(AutoTxByHash)
	err := json.Unmarshal(b, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Query the RPC server then return the AutoTxByHash
func (tool *DebugTool) getAutoTxByHash(txHash string) (*AutoTxByHash, error) {
	if len(tool.url) == 0 {
		return nil, errors.New("Debugtool has not set mainnet or testnet")
	}
	query := fmt.Sprintf(`{
		"jsonrpc":"1.0",
		"method":"gettransactionbyhash",
		"params":["%s"],
		"id":1
	}`, txHash)
	b, err := tool.SendPostRequestWithQuery(query)
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
func (tool *DebugTool) GetProofTransactionByHash(txHash string) (string, error) {
	tx, err := tool.getAutoTxByHash(txHash)
	if err != nil {
		return "", err
	}
	return tx.Result.Proof, nil
}

// Get only the Sig of transaction requiring the txHash
func (tool *DebugTool) GetSigTransactionByHash(txHash string) (string, error) {
	tx, err := tool.getAutoTxByHash(txHash)
	if err != nil {
		return "", err
	}
	return tx.Result.Sig, nil
}

// Get only the BlockHash of transaction requiring the txHash
func (tool *DebugTool) GetBlockHashTransactionByHash(txHash string) (string, error) {
	tx, err := tool.getAutoTxByHash(txHash)
	if err != nil {
		return "", err
	}
	return tx.Result.BlockHash, nil
}

// Get only the BlockHeight of transaction requiring the txHash
func (tool *DebugTool) GetBlockHeightTransactionByHash(txHash string) (int, error) {
	tx, err := tool.getAutoTxByHash(txHash)
	if err != nil {
		return -1, err
	}
	return tx.Result.BlockHeight, nil
}

// Get the whole result of rpc call 'gettransactionbyhash'
func (tool *DebugTool) GetTransactionByHash(txHash string) ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	query := fmt.Sprintf(`{
		"jsonrpc":"1.0",
		"method":"gettransactionbyhash",
		"params":["%s"],
		"id":1
	}`, txHash)
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) CreateAndSendTransaction() ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
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
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) CreateAndSendTransactionFromAToB(privKeyA string, paymentAddress string, amount string) ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
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
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) GetBalanceByPrivatekey(privKeyStr string) ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}

	query := fmt.Sprintf(`{
	   "jsonrpc":"1.0",
	   "method":"getbalancebyprivatekey",
	   "params":["%s"],
	   "id":1
	}`, privKeyStr)

	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) SubmitKey(privKeyStr string) ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}

	query := fmt.Sprintf(`{
	   "jsonrpc":"1.0",
	   "method":"submitkey",
	   "params":["%s"],
	   "id":1
	}`, privKeyStr)

	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) CreateAndSendPrivacyCustomTokenTransaction(privKeyStr, tokenName string) ([]byte, error) {
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
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) TransferPrivacyCustomToken(privKeyStrA string, paymentAddress string, tokenID string, amount string) ([]byte, error) {

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
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) GetBalancePrivacyCustomToken(privKeyStr string, tokenID string) ([]byte, error) {
	query := fmt.Sprintf(`{
		"id": 1,
		"jsonrpc": "1.0",
		"method": "getbalanceprivacycustomtoken",
		"params": [
			"%s",
			"%s"
		]
	}`, privKeyStr, tokenID)
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) SwitchTokenCoinVersion(privKey string, tokenID string) ([]byte, error) {
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
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) SwitchCoinVersion(privKey string) ([]byte, error) {
	query := fmt.Sprintf(`{
		"jsonrpc": "1.0",
		"method": "createconvertcoinver1tover2transaction",
		"params": [
			"%s",
			1
		],
		"id": 1
	}`, privKey)
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) CreateRawTxToken(privateKey, tokenIDString, paymentString string, amount uint64, isPrivacy bool) ([]byte, error) {
	// fmt.Println("Hi i'm here")
	query := fmt.Sprintf(`{
		"id": 1,
		"jsonrpc": "1.0",
		"method": "createrawprivacycustomtokentransaction",
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
					"%s": %d
				}
			}
		]
	}`, privateKey, tokenIDString, paymentString, amount)
	// fmt.Println("trying to send")
	// fmt.Println(query)

	respondInBytes, err := tool.SendPostRequestWithQuery(query)
	if err != nil {
		return nil, err
	}
	// fmt.Println(string(respondInBytes))


	respond, err := ParseResponse(respondInBytes)
	if err != nil {
		return nil, err
	}

	if respond.Error != nil {
		return nil, errors.New(fmt.Sprintf("response error: %v", respond.Error))
	}

	var msg json.RawMessage
	err = json.Unmarshal(respond.Result, &msg)

	var result map[string]interface{}
	err = json.Unmarshal(msg, &result)

	base58Check, ok := result["Base58CheckData"]
	if !ok {
		fmt.Println(result)
		return nil, errors.New("cannot find base58CheckData")
	}

	tmp, _ := base58Check.(string)

	bytearrays, err := DecodeBase58Check(tmp)
	if err != nil {
		return nil, err
	}

	return bytearrays, nil
}

func (tool *DebugTool) CreateRawTx(privateKey, paymentString string, amount uint64, isPrivacy bool) ([]byte, error) {
	privIndicator := "-1"
	if isPrivacy{
		privIndicator = "1"
	}
	query := fmt.Sprintf(`{
		"jsonrpc": "1.0",
		"method": "createtransaction",
		"params": [
			"%s",
			{
				"%s":%d
			},
			1,
			%s
		],
		"id": 1
	}`, privateKey, paymentString, amount, privIndicator)

	respondInBytes, err := tool.SendPostRequestWithQuery(query)
	if err != nil {
		return nil, err
	}

	respond, err := ParseResponse(respondInBytes)
	if err != nil {
		return nil, err
	}

	if respond.Error != nil {
		return nil, errors.New(fmt.Sprintf("response error: %v", respond.Error))
	}

	var msg json.RawMessage
	err = json.Unmarshal(respond.Result, &msg)

	var result map[string]interface{}
	err = json.Unmarshal(msg, &result)

	base58Check, ok := result["Base58CheckData"]
	if !ok {
		fmt.Println(result)
		return nil, errors.New("cannot find base58CheckData")
	}

	tmp, _ := base58Check.(string)

	bytearrays, err := DecodeBase58Check(tmp)
	if err != nil {
		return nil, err
	}

	return bytearrays, nil
}
