package debugtool

import (
	"errors"
)

func (tool *DebugTool) GetBlockchainInfo() ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc":"1.0",
		"method":"getblockchaininfo",
		"params": "",
		"id":1
	}`
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) GetBestBlock() ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc":"1.0",
		"method":"getbestblock",
		"params": "",
		"id":1
	}`
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) GetBestBlockHash() ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc":"1.0",
		"method":"getbestblockhash",
		"params": "",
		"id":1
	}`
	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) GetBeaconBestState() ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	query := `{  
	   "jsonrpc":"1.0",
	   "method":"getbeaconbeststatedetail",
	   "params":[],
	   "id":1
	}`

	return tool.SendPostRequestWithQuery(query)
}

func (tool *DebugTool) GetRawMempool() ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	query := `{
		"jsonrpc": "1.0",
		"method": "getrawmempool",
		"params": "",
		"id": 1
	}`
	return tool.SendPostRequestWithQuery(query)
}