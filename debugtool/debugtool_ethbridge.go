package debugtool

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	rCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/light"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/metadata"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"strconv"
)

type ETHDepositProof struct {
	blockNumber uint
	blockHash rCommon.Hash
	txIdx uint
	nodeList []string
}

func (E ETHDepositProof) TxIdx() uint {
	return E.txIdx
}

func (E ETHDepositProof) BlockNumber() uint {
	return E.blockNumber
}

func (E ETHDepositProof) BlockHash() rCommon.Hash {
	return E.blockHash
}

func (E ETHDepositProof) NodeList() []string {
	return E.nodeList
}

func NewETHDepositProof(blockNumber uint, blockHash rCommon.Hash, txIdx uint, nodeList []string) *ETHDepositProof {
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
	blockHashStr, ok := txContent["blockHash"].(string)
	if !ok {
		return nil, errors.New(fmt.Sprintf("cannot parse blockHash in %v", txContent))
	}
	blockHash := rCommon.HexToHash(blockHashStr)

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

	blockHeader, err := GetETHBlockByHash(url, blockHashStr)
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

	return NewETHDepositProof(uint(blockNumber), blockHash, uint(txIndex), encNodeList), nil
}

func CreateIssuingETHRequestTransaction(privateKey string, ethTxHash string, tokenIDStr string, amount uint64) ([]byte, string, error) {
	proof, err := GetETHDepositProof("", ethTxHash)
	if err != nil {
		return nil, "", err
	}

	tokenID, err := new(common.Hash).NewHashFromStr(tokenIDStr)
	if err != nil {
		return nil, "", err
	}

	var issuingETHRequestMeta *metadata.IssuingETHRequest
	issuingETHRequestMeta, err = metadata.NewIssuingETHRequest(proof.BlockHash(), proof.TxIdx(), proof.NodeList(), *tokenID, metadata.IssuingETHRequestMeta)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot init issue eth request for %v, tokenID %v with amount %v: %v", *proof, tokenIDStr, amount, err))
	}

	txParam := NewTxParam(privateKey, []string{common.BurningAddress2}, []uint64{0}, tokenIDStr, 1, issuingETHRequestMeta)


	return CreateRawTokenTransaction(txParam, -1)
}

func CreateAndSendIssuingETHRequestTransaction(privateKey string, ethTxHash string, tokenIDStr string, amount uint64) (string, error) {
	encodedTx, txHash, err := CreateIssuingETHRequestTransaction(privateKey, ethTxHash, tokenIDStr, amount)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTokenTx(string(encodedTx))
	if err != nil {
		return "", err
	}

	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}
