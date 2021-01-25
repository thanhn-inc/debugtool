package debugtool

import (
	"encoding/json"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/jsonresult"
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

func GetBestBlock() (map[int]uint64, error) {
	responseInBytes, err := rpc.GetBestBlock()
	if err != nil {
		return nil, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return nil, err
	}

	var bestBlocksResult jsonresult.GetBestBlockResult
	err = json.Unmarshal(response.Result, &bestBlocksResult)
	if err != nil {
		return nil, err
	}

	res := make(map[int]uint64)

	for key, value := range bestBlocksResult.BestBlocks {
		res[key] = value.Height
	}

	return res, nil
}