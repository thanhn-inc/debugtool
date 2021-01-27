package rpchandler

import (
	"bytes"
	"errors"
	"github.com/thanhn-inc/debugtool/common"
	"io/ioutil"
	"net/http"
)

type RPCServer struct {
	url string
}

func (server *RPCServer) GetURL() string {
	return server.url
}

func (server *RPCServer) InitToURL(url string) *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = url
	return server
}

func (server *RPCServer) SendPostRequestWithQuery(query string) ([]byte, error) {
	if len(server.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	var jsonStr = []byte(query)
	req, _ := http.NewRequest("POST", server.url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return []byte{}, err
		}
		return body, nil
	}
}

func InitMainNet() {
	Server.url = "https://mainnet.incognito.org/fullnode"
	EthServer.url = "https://mainnet.infura.io/v3/34918000975d4374a056ed78fe21c517"
	common.EthContractAddressStr = common.MainETHContractAddressStr
	return
}

func InitTestNet() {
	if Server == nil {
		Server = new(RPCServer)
	}
	Server.url = "http://51.83.36.184:20002"
	EthServer.url = "https://kovan.infura.io/v3/93fe721349134964aa71071a713c5cef"
	common.EthContractAddressStr = common.TestnetETHContractAddressStr
}

func InitLocal(port string) {
	if Server == nil {
		Server = new(RPCServer)
	}
	if EthServer == nil {
		EthServer = new(RPCServer)
	}
	Server.url = "http://127.0.0.1:" + port
}

func InitDevNet() {
	if Server == nil {
		Server = new(RPCServer)
	}
	if EthServer == nil {
		EthServer = new(RPCServer)
	}

	Server.url = "http://139.162.55.124:8334"
	EthServer.url = "https://kovan.infura.io/v3/93fe721349134964aa71071a713c5cef"
	common.EthContractAddressStr = common.TestnetETHContractAddressStr
}
