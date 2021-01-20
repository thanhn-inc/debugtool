package rpc

import (
	"errors"
	"github.com/thanhn-inc/debugtool/rpchandler"
)

func GetBlockchainInfo() ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc":"1.0",
		"method":"getblockchaininfo",
		"params": "",
		"id":1
	}`
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func GetBestBlock() ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc":"1.0",
		"method":"getbestblock",
		"params": "",
		"id":1
	}`
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func GetBestBlockHash() ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc":"1.0",
		"method":"getbestblockhash",
		"params": "",
		"id":1
	}`
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func GetBeaconBestState() ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	query := `{  
	   "jsonrpc":"1.0",
	   "method":"getbeaconbeststatedetail",
	   "params":[],
	   "id":1
	}`

	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func GetRawMempool() ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc": "1.0",
		"method": "getrawmempool",
		"params": "",
		"id": 1
	}`
	return rpchandler.Server.SendPostRequestWithQuery(query)
}