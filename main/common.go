package main

import (
	"encoding/json"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/debugtool"
	"github.com/thanhn-inc/debugtool/incognitokey"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/wallet"
	"strconv"
	"time"
)

var mainNetTokenIDs = map[string]string {
	"USDT": "716fd1009e2a1669caacc36891e707bfdf02590f96ebd897548e8963c95ebac0",
	"BNB": "b2655152784e8639fa19521a7035f331eea1f1e911b2f3200a507ebb4554387b",
	"ETH": "ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f",
	"USDC": "1ff2da446abfebea3ba30385e2ca99b0f0bbeda5c6371f4c23c939672b429a42",
	"XMR": "c01e7dc1d1aba995c19b257412340b057f8ad1482ccb6a9bb0adce61afbf05d4",
	"BTC": "b832e5d3b1f01a4f0623f7fe91d6673461e1f5d37d91fe78c5c2e6183ff39696",
	"PRV": common.PRVIDStr,
	"TEMP": "0000000000000000000000000000000000000000000000000000000000000100",
	"DAI": "3f89c75324b46f13c7b036871060e641d996a24c09b3065835cb1d38b799d6c1",
}

//Remote network-related functions
func InitMainNet() error {
	rpchandler.InitMainNet()

	activeShards, err := debugtool.GetActiveShard()
	if err != nil {
		return err
	}

	fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
	common.MaxShardNumber = activeShards

	common.SupportedTokenID = mainNetTokenIDs

	return nil
}
func InitTestNet() error {
	rpchandler.InitTestNet()

	activeShards, err := debugtool.GetActiveShard()
	if err != nil {
		return err
	}

	fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
	common.MaxShardNumber = activeShards

	common.SupportedTokenID = mainNetTokenIDs

	return nil
}
func InitDevNet(port string) error {
	rpchandler.InitDevNet(port)

	activeShards, err := debugtool.GetActiveShard()
	if err != nil {
		return err
	}

	fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
	common.MaxShardNumber = activeShards

	common.SupportedTokenID = mainNetTokenIDs

	return nil
}
func InitLocal(port string) error {
	rpchandler.InitLocal(port)

	activeShards, err := debugtool.GetActiveShard()
	if err != nil {
		return err
	}

	fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
	common.MaxShardNumber = activeShards

	common.SupportedTokenID = mainNetTokenIDs

	return nil
}
func SwitchPort(newPort string) error {
	rpchandler.Server = new(rpchandler.RPCServer).InitToURL(fmt.Sprintf("http://127.0.0.1:%v", newPort))

	activeShards, err := debugtool.GetActiveShard()
	if err != nil {
		return err
	}

	fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
	common.MaxShardNumber = activeShards

	common.SupportedTokenID = mainNetTokenIDs

	return nil
}

//Blockchain-related functions
func GetBlockchainInfo() {
	fmt.Println("========== GET BLOCKCHAIN INFO ==========")
	b, _ := rpc.GetBlockchainInfo()
	fmt.Println(string(b))
	fmt.Println("========== END GET BLOCKCHAIN INFO ==========")
}
func GetBeaconBestState() {
	fmt.Println("========== GET BEACON BEST STATE INFO ==========")
	b, _ := rpc.GetBeaconBestState()
	fmt.Println(string(b))
	fmt.Println("========== END GET BEACON BEST STATE INFO ==========")
}
func GetBestBlock() {
	fmt.Println("========== GET BEST BLOCK INFO ==========")
	b, _ := rpc.GetBestBlock()
	fmt.Println(string(b))
	fmt.Println("========== END GET BEST BLOCK INFO ==========")
}
func GetRawMempool() {
	fmt.Println("==================================")
	txList, err := debugtool.GetRawMempool()
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, txHash := range txList {
		fmt.Println(txHash)
	}
	fmt.Printf("%v Number of txs: %v\n", time.Now().String(), len(txList))
	fmt.Println("==================================")
}
func GetTxByHash(txHash string) {
	fmt.Println("========== GET TX BY HASH ==========")
	b, _ := rpc.GetTransactionByHash(txHash)
	fmt.Println(string(b))
	fmt.Println("========== END GET TX BY HASH ==========")
}

//Key-related functions
func GenerateCommitteeKey(privateKey, seed string) (string, error) {
	public := debugtool.PrivateKeyToPublicKey(privateKey)
	seedBytes, _, err := base58.Base58Check{}.Decode(seed)
	if err != nil {
		return "", err
	}

	committeeKey, err := incognitokey.NewCommitteeKeyFromSeed(seedBytes, public)
	if err != nil {
		return "", err
	}

	return committeeKey.ToBase58()
}
func ParsePrivateKey(arg string, privateKeys []string) (string, error) {
	var privateKey string
	if len(arg) < 3 {
		index, err := strconv.ParseInt(arg, 10, 32)
		if err != nil {
			return "", err
		}
		if index >= int64(len(privateKeys)) {
			return "", fmt.Errorf("Cannot find the private key")
		}
		privateKey = privateKeys[index]
	} else {
		privateKey = arg
	}

	return privateKey, nil
}
func ParsePaymentAddress(arg string, privateKeys []string) (string, error) {
	var paymentAddr string
	if len(arg) < 3 {
		index, err := strconv.ParseInt(arg, 10, 32)
		if err != nil {
			return "", err
		}
		if index >= int64(len(privateKeys)) {
			return "", fmt.Errorf("Cannot find the private key")
		}
		privateKey := privateKeys[index]
		paymentAddr = debugtool.PrivateKeyToPaymentAddress(privateKey, -1)
	} else {
		paymentAddr = arg
	}

	return paymentAddr, nil
}
func ParsePublicKey(arg string, privateKeys []string) (string, error) {
	var publicKey string
	if len(arg) < 3 {
		index, err := strconv.ParseInt(arg, 10, 32)
		if err != nil {
			return "", err
		}
		if index >= int64(len(privateKeys)) {
			return "", fmt.Errorf("Cannot find the private key")
		}
		privateKey := privateKeys[index]
		publicKeyBytes := debugtool.PrivateKeyToPublicKey(privateKey)
		if len(publicKeyBytes) == 0 {
			return "", fmt.Errorf("cannot parse public key %v", arg)
		}
		publicKey = base58.Base58Check{}.Encode(publicKeyBytes, 0)
	} else {
		publicKey = arg
	}

	return publicKey, nil
}
func GenKeySet(b []byte) (string, string, string) {
	if b == nil {
		b = privacy.RandomScalar().ToBytesS()
	}

	seed := privacy.HashToScalar(b).ToBytesS()

	keyWallet, err := wallet.NewMasterKey(seed)
	if err != nil {
		return "", "", ""
	}

	privateKey := keyWallet.Base58CheckSerialize(wallet.PriKeyType)
	paymentAddress := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	readOnly := keyWallet.Base58CheckSerialize(wallet.ReadonlyKeyType)

	return privateKey, paymentAddress, readOnly
}

//Token-related functions
func ListTokens() {
	fmt.Println("========== LIST ALL TOKEN ==========")
	b, _ := rpc.ListPrivacyCustomTokenByRPC()
	res := new(rpc.ListCustomToken)
	_ = json.Unmarshal(b, res)
	fmt.Println("Number of Token: ", len(res.Result.ListCustomToken))
	if len(res.Result.ListCustomToken) > 0 {
		for _, token := range res.Result.ListCustomToken {
			fmt.Println("Token ", token.Name, token.ID)
		}
		fmt.Println("========== END LIST ALL TOKEN ==========")
		return
	}
	fmt.Println("========== END LIST ALL TOKEN ==========")
	return
}
func ParseTokenID(arg string) (string, error) {
	if len(arg) < 10 {
		tokenID, ok := common.SupportedTokenID[arg]
		if !ok {
			return "", fmt.Errorf("tokenID %v not found, list of supported tokenIDs: %v", arg, common.SupportedTokenID)
		}
		return tokenID, nil
	}

	return arg, nil
}

//TXO-related functions
func GetTXOs(privateKey string, tokenID string, height uint64) {
	fmt.Println("========== GET PRV OUTPUT COIN ==========")
	outCoinKey, err := debugtool.NewOutCoinKeyFromPrivateKey(privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	outCoinKey.SetReadonlyKey("") //Call this if you dont want the full node to decrypt your amount.

	b, err := rpc.GetListOutputCoinsByRPC(outCoinKey, tokenID, height)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(b))
	fmt.Println("========== END GET PRV OUTPUT COIN ==========")
}
func GetUTXOs(privateKey string, tokenID string, height uint64) {
	fmt.Println("========== GET UNSPENT OUTPUT TOKEN ==========")
	listUnspentCoins, _, err := debugtool.GetUnspentOutputCoins(privateKey, tokenID, height)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, unspentCoin := range listUnspentCoins {
		fmt.Printf("version: %v, pubKey: %v, keyImage: %v, value: %v\n", unspentCoin.GetVersion(), unspentCoin.GetPublicKey(), unspentCoin.GetKeyImage(), unspentCoin.GetValue())
	}

	fmt.Println("========== END UNSPENT OUTPUT TOKEN ==========")
}