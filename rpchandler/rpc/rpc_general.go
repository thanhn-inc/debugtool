package rpc

import (
	"encoding/json"
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