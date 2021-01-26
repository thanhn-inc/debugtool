package rpchandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/incognitokey"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/wallet"
)

// RPCError represents an error that is used as a part of a JSON-RPC JsonResponse
// object.
type RPCError struct {
	Code       int    `json:"Code,omitempty"`
	Message    string `json:"Message,omitempty"`
	StackTrace string `json:"StackTrace"`

	err 	   error  `json:"Err"`
}

type JsonRequest struct {
	Jsonrpc string      `json:"Jsonrpc"`
	Method  string      `json:"Method"`
	Params  interface{} `json:"Params"`
	Id      interface{} `json:"Id"`
}

type JsonResponse struct {
	Id      *interface{}         `json:"Id"`
	Result  json.RawMessage      `json:"Result"`
	Error   *RPCError 			 `json:"Error"`
	Params  interface{}          `json:"Params"`
	Method  string               `json:"Method"`
	Jsonrpc string               `json:"Jsonrpc"`
}

var Server = new(RPCServer).InitTestnet()
var EthServer = new(RPCServer).InitTestnet()

func EncodeBase58Check(data []byte) string {
	b := base58.Base58Check{}.Encode(data, 0)
	return b
}

func DecodeBase58Check(s string) ([]byte, error) {
	b, _, err := base58.Base58Check{}.Decode(s)
	return b, err
}

/*Common functions*/
// RandIntInterval returns a random int in range [L; R]
func RandIntInterval(L, R int) int {
	length := R - L + 1
	r := common.RandInt() % length
	return L + r
}

func ParseResponse(respondInBytes []byte) (*JsonResponse, error) {
	var respond JsonResponse
	err := json.Unmarshal(respondInBytes, &respond)
	if err != nil {
		return nil, err
	}

	if respond.Error != nil{
		return nil, errors.New(fmt.Sprintf("RPC returns an error: %v", respond.Error))
	}

	return &respond, nil
}

func CreateJsonRequest(jsonRPC, method string, params []interface{}, id interface{}) *JsonRequest{
	request := new(JsonRequest)
	request.Jsonrpc = jsonRPC
	request.Method = method
	request.Id = id
	request.Params = params

	return request
}

//Temp function that creates a payment address of a specific shard.
func CreatePaymentAddress(shardID byte) string {
	pk := common.RandBytes(31)
	tk := common.RandBytes(32)

	//Set last byte of pk to be the shardID
	pk = append(pk, shardID)

	addr := privacy.PaymentAddress{pk, tk, nil}

	keyWallet := new(wallet.KeyWallet)
	keyWallet.KeySet = incognitokey.KeySet{PaymentAddress: addr}

	return keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
}