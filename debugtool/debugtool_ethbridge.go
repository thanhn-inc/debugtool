package debugtool

import (
	"encoding/json"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
)

func GetETHTxByHash(url string, txHash string) (map[string]interface{}, error) {
	responseInBytes, err := rpc.GetETHTransactionByHash(url, txHash)
	if err != nil {
		return nil, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return nil, err
	}

	var res map[string]interface{}
	err = json.Unmarshal(response.Result, &res)

	return res, nil
}

