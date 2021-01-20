package debugtool

import (
	"encoding/json"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
)

func GetActiveShard() (int, error) {
	responseInBytes, err := rpc.GetActiveShards()
	if err != nil {
		return 0, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return 0, err
	}

	var activeShards int
	err = json.Unmarshal(response.Result, &activeShards)

	return activeShards, err
}