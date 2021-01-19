package debugtool

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
)

type DebugTool struct {
	url string
}

func (tool *DebugTool) GetURL() string {
	return tool.url
}

func (tool *DebugTool) InitMainnet() *DebugTool {
	if tool == nil {
		tool = new(DebugTool)
	}
	tool.url = "https://mainnet.incognito.org/fullnode"
	return tool
}

func (tool *DebugTool) InitTestnet() *DebugTool {
	if tool == nil {
		tool = new(DebugTool)
	}
	tool.url = "http://51.83.36.184:20002"
	return tool
}

func (tool *DebugTool) InitLocal(port string) *DebugTool {
	if tool == nil {
		tool = new(DebugTool)
	}
	tool.url = "http://127.0.0.1:" + port
	return tool
}

func (tool *DebugTool) InitDevNet() *DebugTool {
	if tool == nil {
		tool = new(DebugTool)
	}
	tool.url = "http://139.162.55.124:8334"
	return tool
}

func (tool *DebugTool) SendPostRequestWithQuery(query string) ([]byte, error) {
	if len(tool.url) == 0 {
		return []byte{}, errors.New("Debugtool has not set mainnet or testnet")
	}
	var jsonStr = []byte(query)
	req, _ := http.NewRequest("POST", tool.url, bytes.NewBuffer(jsonStr))
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
