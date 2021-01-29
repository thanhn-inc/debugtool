package rpc

import (
	"encoding/json"
	"errors"
	"github.com/thanhn-inc/debugtool/rpchandler"
)

func GetActiveShards() ([]byte, error) {
	method := getActiveShards

	params := make([]interface{}, 0)
	request := rpchandler.CreateJsonRequest("1.0", method, params, 1)

	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.Server.SendPostRequestWithQuery(string(query))
}

func GetShardBestState(shardID byte) ([]byte, error) {
	if len(rpchandler.Server.GetURL()) == 0 {
		return []byte{}, errors.New("Server has not set mainnet or testnet")
	}
	method := getShardBestState
	params := make([]interface{}, 0)
	params = append(params, shardID)

	request := rpchandler.CreateJsonRequest("1.0", method, params, 1)
	query, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return rpchandler.Server.SendPostRequestWithQuery(string(query))
}
