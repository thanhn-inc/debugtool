package rpchandler

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
)

type RPCServer struct {
	url string
}

func (server *RPCServer) GetURL() string {
	return server.url
}

func (server *RPCServer) InitMainnet() *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = "https://mainnet.incognito.org/fullnode"
	return server
}

func (server *RPCServer) InitTestnet() *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = "http://51.83.36.184:20002"
	return server
}

func (server *RPCServer) InitLocal(port string) *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = "http://127.0.0.1:" + port
	return server
}

func (server *RPCServer) InitDevNet() *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = "http://139.162.55.124:8334"
	return server
}

func (server *RPCServer) InitToURL(url string) *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = url
	return server
}

func (server *RPCServer) InitEthBridgeMainNet() *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = "https://mainnet.infura.io/v3/34918000975d4374a056ed78fe21c517"
	return server
}

func (server *RPCServer) InitEthBridgeTestNet() *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = "https://kovan.infura.io/v3/93fe721349134964aa71071a713c5cef"
	return server
}

func (server *RPCServer) InitEthBridgeDevNet() *RPCServer {
	if server == nil {
		server = new(RPCServer)
	}
	server.url = "https://kovan.infura.io/v3/93fe721349134964aa71071a713c5cef"
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

func (server *RPCServer) SendPostRequestWithQuery2(query string) ([]byte, error) {
	if len(server.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	client := new(http.Client)

	resp, err := client.Post(server.GetURL(), "application/json", bytes.NewBuffer([]byte(query)))
	if err != nil {
		return nil, err
	}

	respBody := resp.Body
	defer respBody.Close()

	body, err := ioutil.ReadAll(respBody)
	if err != nil {
		return nil, err
	}

	return body, nil
}