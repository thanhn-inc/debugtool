package rpc

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/thanhn-inc/debugtool/rpchandler"
)

type Receipt struct {
	Result *types.Receipt `json:"result"`
}

type NormalResult struct {
	Result interface{} `json:"result"`
}

func GetETHTransactionByHash(
	url string,
	tx string,
) ([]byte, error) {
	if len(url) != 0 {
		rpchandler.EthServer.InitToURL(url)
	}

	method := "eth_getTransactionByHash"
	params := []interface{}{tx}

	request := rpchandler.CreateJsonRequest("2.0", method, params, 1)
	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.EthServer.SendPostRequestWithQuery2(string(query))
}

func GetETHBlockByHash(
	url string,
	blockHash string,
) ([]byte, error) {
	if len(url) != 0 {
		rpchandler.EthServer.InitToURL(url)
	}

	method := "eth_getBlockByHash"
	params := []interface{}{blockHash, false}

	request := rpchandler.CreateJsonRequest("2.0", method, params, 1)
	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.EthServer.SendPostRequestWithQuery(string(query))
}

func GetETHTransactionReceipt(url string, txHash string) ([]byte, error) {
	if len(url) != 0 {
		rpchandler.EthServer.InitToURL(url)
	}

	method := "eth_getTransactionReceipt"
	params := []interface{}{txHash}

	request := rpchandler.CreateJsonRequest("2.0", method, params, 1)
	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.EthServer.SendPostRequestWithQuery(string(query))
}
