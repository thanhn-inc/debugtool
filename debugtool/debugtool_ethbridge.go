package debugtool

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/light"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"strconv"
)

type ETHDepositProof struct {
	blockNumber uint64
	blockHash string
	txIdx uint64
	nodeList []string
}

func (E ETHDepositProof) TxIdx() uint64 {
	return E.txIdx
}

func (E ETHDepositProof) BlockNumber() uint64 {
	return E.blockNumber
}

func (E ETHDepositProof) BlockHash() string {
	return E.blockHash
}

func (E ETHDepositProof) NodeList() []string {
	return E.nodeList
}

func NewETHDepositProof(blockNumber uint64, blockHash string, txIdx uint64, nodeList []string) *ETHDepositProof {
	proof := ETHDepositProof{
		blockNumber: blockNumber,
		blockHash:   blockHash,
		txIdx:       txIdx,
		nodeList:    nodeList,
	}

	return &proof
}

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

func GetETHBlockByHash(url string, blockHash string) (map[string]interface{}, error) {
	responseInBytes, err := rpc.GetETHBlockByHash(url, blockHash)
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

func GetETHTxReceipt(url string, txHash string) (*types.Receipt, error) {
	responseInBytes, err := rpc.GetETHTransactionReceipt(url, txHash)
	if err != nil {
		return nil, err
	}

	response, err := rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return nil, err
	}

	var res types.Receipt
	err = json.Unmarshal(response.Result, &res)

	return &res, nil
}


func GetETHDepositProof(url string, txHash string) (*ETHDepositProof, error) {
	// Get tx content
	txContent, err := GetETHTxByHash(url, txHash)
	if err != nil {
		fmt.Println("cannot get eth by hash", err)
		return nil, err
	}

	_, ok := txContent["blockHash"]
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot find blockHash in %v", txContent))
	}
	blockHash, ok := txContent["blockHash"].(string)
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot parse blockHash in %v", txContent))
	}

	_, ok = txContent["transactionIndex"]
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot find transactionIndex in %v", txContent))
	}
	txIndexStr, ok := txContent["transactionIndex"].(string)
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot parse transactionIndex in %v", txContent))
	}

	txIndex, err := strconv.ParseUint(txIndexStr[2:], 16, 64)
	if err != nil {
		return nil, err
	}

	// Get tx's block for constructing receipt trie
	_, ok = txContent["blockNumber"]
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot find blockNumber in %v", txContent))
	}
	blockNumString, ok := txContent["blockNumber"].(string)
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot parse blockNumber in %v", txContent))
	}
	blockNumber, err := strconv.ParseInt(blockNumString[2:], 16, 64)
	if err != nil {
		return nil, errors.New("cannot convert blockNumber into integer")
	}

	blockHeader, err := GetETHBlockByHash(url, blockHash)
	if err != nil {
		return nil, err
	}

	// Get all sibling Txs
	_, ok = blockHeader["transactions"]
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot find transactions in %v", txContent))
	}
	siblingTxs, ok := blockHeader["transactions"].([]interface{})
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot parse transactions in %v", txContent))
	}

	// Constructing the receipt trie (source: go-ethereum/core/types/derive_sha.go)
	keyBuf := new(bytes.Buffer)
	receiptTrie := new(trie.Trie)
	for i, tx := range siblingTxs {
		siblingReceipt, err := GetETHTxReceipt(url, tx.(string))
		if err != nil {
			return nil, err
		}
		keyBuf.Reset()
		err = rlp.Encode(keyBuf, uint(i))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("rlp encode returns an error: %v", err))
		}
		encodedReceipt, err := rlp.EncodeToBytes(siblingReceipt)
		if err != nil {
			return nil, err
		}
		receiptTrie.Update(keyBuf.Bytes(), encodedReceipt)
	}

	// Constructing the proof for the current receipt (source: go-ethereum/trie/proof.go)
	proof := light.NewNodeSet()
	keyBuf.Reset()
	err = rlp.Encode(keyBuf, uint(txIndex))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("rlp encode returns an error: %v", err))
	}
	err = receiptTrie.Prove(keyBuf.Bytes(), 0, proof)
	if err != nil {
		return nil, err
	}

	nodeList := proof.NodeList()
	encNodeList := make([]string, 0)
	for _, node := range nodeList {
		str := base64.StdEncoding.EncodeToString(node)
		encNodeList = append(encNodeList, str)
	}

	return NewETHDepositProof(uint64(blockNumber), blockHash, txIndex, encNodeList), nil
}
