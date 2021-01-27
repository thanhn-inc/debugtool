package rpc

import (
	"encoding/json"
	"github.com/thanhn-inc/debugtool/rpchandler"
)

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

	return rpchandler.EthServer.SendPostRequestWithQuery(string(query))
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
