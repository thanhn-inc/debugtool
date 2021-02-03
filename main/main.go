package main

import (
	"bufio"
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
	"math/big"
	"os"
	"strconv"
	"strings"
)

//Misc
func SwitchPort(newPort string) {
	rpchandler.Server = new(rpchandler.RPCServer).InitToURL(fmt.Sprintf("http://127.0.0.1:%v", newPort))
}
func GetShardIDFromPrivateKey(privateKey string) byte {
	pubkey := debugtool.PrivateKeyToPublicKey(privateKey)
	return common.GetShardIDFromLastByte(pubkey[len(pubkey)-1])
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

//Outcoins
func GetPRVOutPutCoin(privkey string, height uint64) {
	fmt.Println("========== GET PRV OUTPUT COIN ==========")
	outCoinKey, err := debugtool.NewOutCoinKeyFromPrivateKey(privkey)
	if err != nil {
		fmt.Println(err)
		return
	}
	outCoinKey.SetReadonlyKey("") //Call this if you dont want the full node to decrypt your amount.

	b, err := rpc.GetListOutputCoinsByRPC(outCoinKey, common.PRVIDStr, height)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(b))
	fmt.Println("========== END GET PRV OUTPUT COIN ==========")
}
func GetUnspentOutputToken(privKey string, tokenID string, height uint64) {
	fmt.Println("========== GET UNSPENT OUTPUT TOKEN ==========")
	listUnspentCoins, _, err := debugtool.GetUnspentOutputCoins(privKey, tokenID, height)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, unspentCoin := range listUnspentCoins {
		fmt.Printf("version: %v, pubKey: %v, keyImage: %v, value: %v\n", unspentCoin.GetVersion(), unspentCoin.GetPublicKey(), unspentCoin.GetKeyImage(), unspentCoin.GetValue())
	}

	fmt.Println("========== END UNSPENT OUTPUT TOKEN ==========")
}
func GetBalance(privkey, tokenID string) {
	fmt.Println("========== GET BALACE ==N========")
	b, _ := debugtool.GetBalance(privkey, tokenID)
	fmt.Println(string(b))
	fmt.Println("========== END GET BALANCE ==========")
}

//PDEX
func GetPDEState(beaconHeight uint64) {
	fmt.Println("========== GET PDE STATE ==========")
	b, err := rpc.GetPDEState(beaconHeight)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
	fmt.Println("========== END GET PDE STATE ==========")
}

//Token
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

func ParseTokenID(arg string, tokenIDs map[string]string) (string, error) {
	if len(arg) < 10 {
		tokenID, ok := tokenIDs[arg]
		if !ok {
			return "", fmt.Errorf("tokenID %v not found, list of supported tokenIDs: %v", arg, tokenIDs)
		}
		return tokenID, nil
	}

	return arg, nil
}

//Transactions
func TransferPRV(tool *rpchandler.RPCServer, fromPrivKey, paymentAddress, amount string) {
	fmt.Println("========== TRANSFER PRV  ==========")
	b, _ := rpc.CreateAndSendTransactionFromAToB(fromPrivKey, paymentAddress, amount)
	fmt.Println(string(b))
	fmt.Println("========== END TRANSFER PRV  ==========")
}

func sendTx() {
	b, _ := rpc.CreateAndSendTransaction()
	fmt.Println(string(b))
}

//Blockchain
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
	fmt.Println("========== GET RAW MEMPOOL ==========")
	b, _ := rpc.GetRawMempool()
	fmt.Println(string(b))
	fmt.Println("========== END GET RAW MEMPOOL ==========")
}
func GetTxByHash(txHash string) {
	fmt.Println("========== GET TX BY HASH ==========")
	b, _ := rpc.GetTransactionByHash(txHash)
	fmt.Println(string(b))
	fmt.Println("========== END GET TX BY HASH ==========")
}

func Init() error {
	rpchandler.InitLocal("9334")
	//rpchandler.Server = new(rpchandler.RPCServer).InitDevNet()
	//rpchandler.Server = new(rpchandler.RPCServer).InitTestnet()

	activeShards, err := debugtool.GetActiveShard()
	if err != nil {
		return err
	}

	fmt.Printf("Init to: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), activeShards)
	common.MaxShardNumber = activeShards

	return nil
}

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

//Comment the init function in blockchain/constants.go to run the debug tool.
func main() {
	privateKeys := []string{
		"112t8roafGgHL1rhAP9632Yef3sx5k8xgp8cwK4MCJsCL1UWcxXvpzg97N4dwvcD735iKf31Q2ZgrAvKfVjeSUEvnzKJyyJD3GqqSZdxN4or",
		"112t8rnZDRztVgPjbYQiXS7mJgaTzn66NvHD7Vus2SrhSAY611AzADsPFzKjKQCKWTgbkgYrCPo9atvSMoCf9KT23Sc7Js9RKhzbNJkxpJU6",
		"112t8rne7fpTVvSgZcSgyFV23FYEv3sbRRJZzPscRcTo8DsdZwstgn6UyHbnKHmyLJrSkvF13fzkZ4e8YD5A2wg8jzUZx6Yscdr4NuUUQDAt",
		"112t8rnXoBXrThDTACHx2rbEq7nBgrzcZhVZV4fvNEcGJetQ13spZRMuW5ncvsKA1KvtkauZuK2jV8pxEZLpiuHtKX3FkKv2uC5ZeRC8L6we",
		"112t8rnbcZ92v5omVfbXf1gu7j7S1xxr2eppxitbHfjAMHWdLLBjBcQSv1X1cKjarJLffrPGwBhqZzBvEeA9PhtKeM8ALWiWjhUzN5Fi6WVC",
		"112t8rnZUQXxcbayAZvyyZyKDhwVJBLkHuTKMhrS51nQZcXKYXGopUTj22JtZ8KxYQcak54KUQLhimv1GLLPFk1cc8JCHZ2JwxCRXGsg4gXU",
		"112t8rnXDS4cAjFVgCDEw4sWGdaqQSbKLRH1Hu4nUPBFPJdn29YgUei2KXNEtC8mhi1sEZb1V3gnXdAXjmCuxPa49rbHcH9uNaf85cnF3tMw",
		"112t8rnYoioTRNsM8gnUYt54ThWWrRnG4e1nRX147MWGbEazYP7RWrEUB58JLnBjKhh49FMS5o5ttypZucfw5dFYMAsgDUsHPa9BAasY8U1i",
		"112t8rnXtw6pWwowv88Ry4XxukFNLfbbY2PLh2ph38ixbCbZKwf9ZxVjd4s7jU3RSdKctC7gGZp9piy8nZoLqHwqDBWcsMHWsQg27S5WCdm4",
		"",
		"1111111AGn6ApFymmmPHK93oBdRHErvZd4Kg96Fgfg8gUqgSiuzENo44rUwcK2i8fQw4pd9cYzjWMe7wrSQ77cPASQfg5r6WiTSwNmtcB7d",
		"1111111ANLMS7hN5kXA9PrPYbGAb4EPCTtCUnm1T756dMqVSgyiw6HUXjpxQBAvqx7UusyRYLKFfmUzaS9EvJFDPS72uPtX73HYHEi7Un5h",
		"1111111ALNQyX2N8pqMtm559yPyutwenzJEToTfJAmxx3VJ8N4QHZsyWznRTeWDqiRahHCEf9owKyzEuqDkHgYnWfVx4j74UNuvAAdCFrur",
		"1111111EEeZcK1AHDVP9RcsQm3PBs1fU2ZmJmAUViKjMsJoiAwFjw1HJRHv1EDdbB1SXFgXSFiuRwGAzE6GPPaUNfAyqJyLy7yT5qx3f4rJ",
		"11111116ZC2uQaFqDNNVyYRaytNyPD5gnYinMDETFjCPdfe2DfpdP1VyZDJD72esH4oauT1FbSyoBRovnb5zrPiBAW5o28tHpxXKsGLypta",
		"1111111848Et3EqTnpJzoUyvW1xFeybgaZ9XuoZgTywKh6zVFaqYk5wU4zPw4Q6iBUxU3fSemXWRA8a72VAwa7CxujuwQAaoo9CyUEqczXL",
		"1111111591Zh66MGKjcHwkhdzqRhgwASJnLGVScJiBw6ZZVUStTRzEDsiYBT2EZmheZgREjzg5wrj3UTqstkQHwfkHc1QP4y91QyQwTX8z",
		"111111165vjf5eCgiT7ZeFgmoVP44n2CYChRUw2rTMejrgwwcocxJPmCituH3ygJvYmKnnFtTkaVAWUAKJySDu2tLC3SpWs1TyjGed8jZ8z",
		"1111111Cjswfvzmhpge7B73ww1GWfj5CNuHcyBt72qNP1ceoaCQ4uHNhDyUNY3xSUeakovcDKTcwUsVvmuacVMamGVo1zbdB9u57Frcxc4p",
		"11111117GB8eNDXhVSdh7mqFw9yWcsMrW2B2yTreXxvDiFsg2WTX79UNDJ9ukxsM14jK3vWqbzvZ1B95XKZh6tWePifWkodNCMLXhF5Bwsv",
	}
	privateSeeds := make(map[string]string)

	tokenIDs := make(map[string]string)
	tokenIDs["USDT"] = "716fd1009e2a1669caacc36891e707bfdf02590f96ebd897548e8963c95ebac0"
	tokenIDs["BNB"] = "b2655152784e8639fa19521a7035f331eea1f1e911b2f3200a507ebb4554387b"
	tokenIDs["ETH"] = "ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f"
	tokenIDs["USDC"] = "1ff2da446abfebea3ba30385e2ca99b0f0bbeda5c6371f4c23c939672b429a42"
	tokenIDs["XMR"] = "c01e7dc1d1aba995c19b257412340b057f8ad1482ccb6a9bb0adce61afbf05d4"
	tokenIDs["BTC"] = "b832e5d3b1f01a4f0623f7fe91d6673461e1f5d37d91fe78c5c2e6183ff39696"
	tokenIDs["PRV"] = common.PRVIDStr
	tokenIDs["TEMP"] = "0000000000000000000000000000000000000000000000000000000000000100"
	tokenIDs["DAI"] = "3f89c75324b46f13c7b036871060e641d996a24c09b3065835cb1d38b799d6c1"

	rpchandler.InitTestNet()
	//rpchandler.InitLocal("9334")

	activeShards, err := debugtool.GetActiveShard()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
	common.MaxShardNumber = activeShards

	reader := bufio.NewReader(os.Stdin)

	//Generate privateSeeds
	for _, privateKey := range privateKeys {
		privateSeedBytes := privacy.HashToScalar([]byte(privateKey)).ToBytesS()
		privateSeed := base58.Base58Check{}.Encode(privateSeedBytes, common.ZeroByte)
		privateSeeds[privateKey] = privateSeed
	}

	for {
		fmt.Print("Enter your choice (arguments separated by ONLY ONE space) and hit ENTER: ")
		text, _ := reader.ReadString('\n')
		args := strings.Split(text[:len(text)-1], " ")
		if len(args) < 1 {
			return
		}

		switch args[0] {
		//Init network
		case "port":
			SwitchPort(args[1])
			activeShards, err := debugtool.GetActiveShard()
			if err != nil {
				panic(err)
			}

			fmt.Printf("Init to: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), activeShards)
			common.MaxShardNumber = activeShards

		case "inittestnet":
			rpchandler.InitTestNet()
			activeShards, err := debugtool.GetActiveShard()
			if err != nil {
				panic(err)
			}

			fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
			common.MaxShardNumber = activeShards

		case "initdevnet":
			port := ""
			if len(args) > 1 {
				port = args[1]
			}
			rpchandler.InitDevNet(port)
			activeShards, err := debugtool.GetActiveShard()
			if err != nil {
				panic(err)
			}

			fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
			common.MaxShardNumber = activeShards

		case "initmainnet":
			rpchandler.InitMainNet()
			activeShards, err := debugtool.GetActiveShard()
			if err != nil {
				panic(err)
			}

			fmt.Printf("Init to: %v, eth server: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), rpchandler.EthServer.GetURL(), activeShards)
			common.MaxShardNumber = activeShards

		case "initlocal":
			port := "9334"
			if len(args) > 1 {
				port = args[1]
			}
			rpchandler.InitLocal(port)
			activeShards, err := debugtool.GetActiveShard()
			if err != nil {
				panic(err)
			}

			fmt.Printf("Init to: %v, number of active shards: %v\n", rpchandler.Server.GetURL(), activeShards)
			common.MaxShardNumber = activeShards

		//PRV RPCs
		case "send":
			addrList := make([]string, 0)
			amountList := make([]uint64, 0)
			for i := 0; i < 8; i++ {
				addr := debugtool.PrivateKeyToPaymentAddress(privateKeys[i+1], -1)
				addrList = append(addrList, addr)
				amountList = append(amountList, 2000000000000)
			}

			for i := 0; i < 10; i++ {
				_, addr, _ := GenKeySet([]byte(fmt.Sprintf("can%v", i)))
				addrList = append(addrList, addr)
				amountList = append(amountList, 2000000000000)
			}

			txHash, err := debugtool.CreateAndSendRawTransaction(privateKeys[0], addrList, amountList, -1, nil)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println("CreateAndSendRawTransaction succeeded. Txhash:", txHash)

		case "outcoin":
			var privateKey string
			if len(args[1]) < 10 {
				index, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					panic(err)
				}
				privateKey = privateKeys[index]
			} else {
				privateKey = args[1]
			}
			bi := big.NewInt(0)
			if len(args) >= 3 {
				_, ok := bi.SetString(args[2], 10)
				if !ok {
					continue
				}
			}

			GetPRVOutPutCoin(privateKey, bi.Uint64())

		case "balance":
			if len(args) < 2 {
				fmt.Println("not enough param for balance")
				continue
			}
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			balance, err := debugtool.GetBalance(privateKey, common.PRVIDStr)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println("Balance =", balance)

		case "transfer":
			if len(args) < 4 {
				fmt.Println("need at least 4 arguments.")
			}
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			paymentAddress, err := ParsePaymentAddress(args[2], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseUint(args[3], 10, 64)
			if err != nil {
				fmt.Println("cannot parse amount", args[3], len(args[3]))
				continue
			}

			//Default version is 2
			txVersion := int8(-1)
			if len(args) > 4 {
				tmpVersion, err := strconv.ParseUint(args[4], 10, 32)
				if err != nil {
					fmt.Println("cannot parse version", err)
					continue
				}
				if tmpVersion > 2 {
					fmt.Println("version invalid", tmpVersion)
					continue
				}
				txVersion = int8(tmpVersion)
			}

			txHash, err := debugtool.CreateAndSendRawTransaction(privateKey, []string{paymentAddress}, []uint64{amount}, txVersion, nil)
			if err != nil {
				fmt.Println("CreateAndSendRawTransaction returns an error:", err)
				continue
			}

			fmt.Printf("CreateAndSendRawTransaction succeeded. TxHash: %v.\n", txHash)

		case "uot":
			if len(args) < 2 {
				fmt.Println("Not enough param for unspentouttoken")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID := common.PRVIDStr
			if len(args) > 2 {
				tokenID, err = ParseTokenID(args[2], tokenIDs)
				if err != nil {
					fmt.Println(err)
					continue
				}
			}

			bi := big.NewInt(0)
			if len(args) >= 4 {
				_, ok := bi.SetString(args[3], 10)
				if !ok {
					continue
				}
			}

			GetUnspentOutputToken(privateKey, tokenID, bi.Uint64())

		//CONVERT RPC
		case "convert": //works for both PRV and tokens
			if len(args) < 2 {
				fmt.Println("need at least 2 arguments.")
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			var tokenID = common.PRVIDStr
			if len(args) > 2 {
				tokenID, err = ParseTokenID(args[2], tokenIDs)
				if err != nil {
					fmt.Println(err)
					continue
				}
			}

			if tokenID == common.PRVIDStr {
				txHash, err := debugtool.CreateAndSendRawConversionTransaction(privateKey)
				if err != nil {
					fmt.Println("CreateAndSendRawConversionTransaction returns an error:", err)
					continue
				}

				fmt.Printf("CreateAndSendRawConversionTransaction succeeded. TxHash: %v.\n", txHash)
			} else {
				txHash, err := debugtool.CreateAndSendRawTokenConversionTransaction(privateKey, tokenID)
				if err != nil {
					fmt.Println("CreateAndSendRawTokenConversionTransaction returns an error:", err)
					continue
				}

				fmt.Printf("CreateAndSendRawTokenConversionTransaction succeeded. TxHash: %v.\n", txHash)
			}

		//TOKEN RPCs
		case "inittoken":
			if len(args) < 3 {
				fmt.Println("need at least 3 arguments.")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseInt(args[2], 10, 64)
			if err != nil {
				fmt.Println("cannot parse amount", args[2])
				continue
			}

			//Default version is 2
			txVersion := int8(-1)
			if len(args) > 3 {
				tmpVersion, err := strconv.ParseUint(args[3], 10, 32)
				if err != nil {
					fmt.Println("cannot parse version", err)
					continue
				}
				if tmpVersion > 2 {
					fmt.Println("version invalid", tmpVersion)
					continue
				}
				txVersion = int8(tmpVersion)
			}

			txHash, err := debugtool.CreateAndSendRawTokenInitTransaction(privateKey, []string{}, []uint64{uint64(amount)}, txVersion)
			if err != nil {
				fmt.Println("CreateAndSendRawTokenInitTransaction returns an error:", err)
				continue
			}

			fmt.Printf("CreateAndSendRawTokenInitTransaction succeeded. TxHash: %v.\n", txHash)

		case "balancetoken":
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			balance, err := debugtool.GetBalance(privateKey, tokenID)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println("Balance =", balance)

		case "transfertoken":
			if len(args) < 5 {
				fmt.Println("need at least 5 arguments.")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			paymentAddress, err := ParsePaymentAddress(args[2], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID, err := ParseTokenID(args[3], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseInt(args[4], 10, 64)
			if err != nil {
				fmt.Println("cannot parse amount", args[4])
				continue
			}

			//Default version is 2
			txVersion := int8(-1)
			if len(args) > 5 {
				tmpVersion, err := strconv.ParseUint(args[5], 10, 32)
				if err != nil {
					fmt.Println("cannot parse version", err)
					continue
				}
				if tmpVersion > 2 {
					fmt.Println("version invalid", tmpVersion)
					continue
				}
				txVersion = int8(tmpVersion)
			}

			hasTokenFee := false
			if len(args) > 6 {
				hasTokenFee = true
			}

			txHash, err := debugtool.CreateAndSendRawTokenTransaction(privateKey, []string{paymentAddress}, []uint64{uint64(amount)}, txVersion, tokenID, hasTokenFee)
			if err != nil {
				fmt.Println("CreateAndSendRawTokenTransaction returns an error:", err)
				continue
			}

			fmt.Printf("CreateAndSendRawTokenTransaction succeeded. TxHash: %v.\n", txHash)

		case "listtoken":
			ListTokens()

		//KEY
		case "payment":
			var err error
			if len(args) < 2 {
				fmt.Println("need at least 2 arguments")
				continue
			}
			privateKey := args[1]
			if len(args[1]) < 3 {
				index, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					fmt.Println(err)
					panic(err)
				}
				if index >= int64(len(privateKeys)) {
					fmt.Println("Cannot find the private key")
					continue
				}
				privateKey = privateKeys[index]
			}

			var keyType = int64(-1)
			if len(args) > 3 {
				keyType, err = strconv.ParseInt(args[2], 10, 32)
				if err != nil {
					fmt.Println(err)
					continue
				}
			}
			fmt.Println("Payment Address", debugtool.PrivateKeyToPaymentAddress(privateKey, int(keyType)))

		case "public":
			var privateKey string
			if len(args[1]) < 3 {
				index, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					fmt.Println(err)
					panic(err)
				}
				if index >= int64(len(privateKeys)) {
					fmt.Println("Cannot find the private key")
					continue
				}
				privateKey = privateKeys[index]
			} else {
				privateKey = args[1]
			}
			pubKeyBytes := debugtool.PrivateKeyToPublicKey(privateKey)
			pubKeyStr := base58.Base58Check{}.Encode(pubKeyBytes, 0x00)
			fmt.Println("Public Key", pubKeyBytes, pubKeyStr)

		case "genkeyset":
			privateKey, payment, _ := GenKeySet([]byte(args[1]))
			fmt.Println(privateKey, payment)

		case "cmkey":
			pri := []string{
				"112t8sw2apGTwoVT2M6adwp1fQvH5KzVsns5GFFEHzLxKTYpqmVTJVCUTAzfkQDNKUondiV6MBCSk9MVDao5RRwuhdjkScMBZ42YJ3hZb6Db",
				"112t8sw37yYFcpGhQnNLsHMbBDDSbW27t3YPMLDSK2q2ZmmZ6iSc1d1K5QkCsdsZ5L3YFaLz2R1KZzJHrAxQNefukYvc5hvKgVBFgatYaDtU",
				"112t8sw3HuTUHxw9U7agDsiBBzoLcjd3Z4o226QzUYHL9sAdHTo82iJ4TaaKZ5ZJzU6EcquxNjGTpxW5kdfrsx1EeRD7WChepy4y4WeUhvXA",
				"112t8sw3X7XahWjLwAjgBe51nF4AKqubXFMAFeumM5ECDr8RFH1FKoqzjRECkuXbqJDGr3sAM3qREixjtMpMgPrg63XdKBGYikiSaH89A53V",
				"112t8sw3swjDhYme56xtqu2Zc1CsodJAekC6FL5Lj7QpV7ZY9WvnyrDQc1W3Vim74dcHFR9QZLcu9LkUpDaziTX4bF39gKMBegWVgBDn6nv4",
				"112t8sw4G9xiRC151H5MWV4Kb1CfXAugPQuecjrnktU7W3JUVqd8LhCMa4jwiqaqnSSdNQvKRTqibA7W9tSKegn16HveZDJs1UC4GP4LiRTn",
				"112t8sw4ZAc1wwbKog9NhE6VqpEiPii4reg8Zc5AVGu7BkxtPYv95dXRJtzP9CkepgzfUwTseNzgHXRovo9oDb8XrEpb5EgFhKdZhwjzHTbd",
				"112t8sw4ijTH6E6gbPhCF6y36zijFfb7T1JnU8GWVSMmWMP85zzmjkoLRH4fF5HkJR8W7uqfnDQ19ARtW9mDmvCUviNNdZ3i39PDhXztjfgM",
				"112t8sw4uNsCeamWRqU1QLiquPbBfGB7HE8qyd7YsBUjSWf3nhcRmoMfyptRDAatJNWBopRTigciNHcPVoZG3bhMKUhrvv6LSzq8FwSwNvBD",
				"112t8sw5AggHj5K7c2gZFqnuUypfRimgLvoxHK8U6yE33wAeU1bV2DLkRVhVDHycwaM5LFwLeVLyMGBCx97FyBx3NTHimNVb9MwjP2BeSDDd",
				"112t8sw5fAsCpef9kSYwit7deNVmwhLs64R6s2cH49rWna8yhyCybKM85sFmegtVnEarWXuaTjvVaxVEu3rDTrz7dyUQcy5m37o3LekSxAWe",
				"112t8sw5ne46SFtGAvvhDMj31LdhJcqsTnkiSz439WJc7xtLsRDiA8uq2AYaCPhi3a56soeSBdqRSwyWSBajv89GrPsQk2svLUonNBCSvHX9",
				"112t8sw6XHCn6jmMAfC47kvrhRVG4o1zKBA41wxfb53S3tHXLZNyWKZWSgSHnEPAHKyEvvho3b4oKLxfNka5LJttkmmYpzq2Wccn6ohvjvKN",
			}

			se := []string{
				"12kkr7NxhnekKKBcn9RNgR31gy6LxqiX51eoexvPQpToGdxm28k",
				"12RpaScwxD4xEC5et5UrkStSjTSTd6djFXT52B8M5U8v23bZ9yK",
				"1aJCk2HxULpcBADDZu7BxZBivTqMJB4kSAyVJeuJNaBCxTfJ1A",
				"1CvVLnKzeWZWGrijrHBo9b5PPy77scgcGhuyPdz6aWGVU9qkji",
				"1e2571JcwDa6nxfW66FSA9NpRpvcMowbU1M7vTXvUR6WJa6AjJ",
				"1eZt6YvHHhiKYBJrCpNj4KnkVNBn46bk11MgokpWYBaPssdBCU",
				"15KssSyWEX3Jw49ktvFFH9rhZfiGhCrqB3KXWFTG2WzSmqD9AS",
				"1cJ6MDSA1mSHezUrgvYDE4F1zvR6V3WviArYJUr8NWQmJzHaQN",
				"1tN2rcueWU4xaZJMNvn7XHk1ybSqeDKhzbr1G8c4v8nZLnnqQ2",
				"1qjRfdYhLaZS5SETLiEaEod3D8dwJpTRPQGN87gyUrt1G9PEWM",
				"12cyENYgnbvBr8xgR7BayWWoZtVXeHGXhY4vhivzf7MuXxBY465",
				"1zHp2owSB8DfeUAGxmL1DhVoiuqcbN3ZtPtLrXYSZWqKLNqr38",
				"1297Jr4CNbE54Ayg5p9Yf1JPEL5ynP1MCnTvKg7vREU14XUU9Gg",
			}

			for i, priKey := range pri {
				cmkey, err := GenerateCommitteeKey(priKey, se[i])
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println(cmkey)
			}

		//BLOCKCHAIN
		case "info":
			GetBlockchainInfo()

		case "beaconstate":
			GetBeaconBestState()

		case "bestblock":
			res, err := debugtool.GetBestBlock()
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println(res)

		case "mempool":
			GetRawMempool()

		case "txhash":
			GetTxByHash(args[1])

		case "shardstate":
			if len(args) < 2 {
				fmt.Println("not enough param for shardstate")
				continue
			}

			shardID, err := strconv.ParseInt(args[1], 10, 32)
			if err != nil {
				fmt.Println(err)
				continue
			}

			b, err := rpc.GetShardBestState(byte(shardID))
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(string(b))

		//PDEX
		case "pdetradeprv":
			if len(args) < 4 {
				fmt.Println("Not enough param for pdetradeprv")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseInt(args[3], 10, 64)
			if err != nil {
				fmt.Println(err)
				continue
			}

			txHash, err := debugtool.CreateAndSendPDETradeTransaction(privateKey, common.PRVIDStr, tokenID, uint64(amount))
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendPDETradeTransaction succeeded. TxHash: %v.\n", txHash)

		case "pdetradetoken":
			if len(args) < 5 {
				fmt.Println("Not enough param for pdetradetoken")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenIDToSell, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenIDToBuy, err := ParseTokenID(args[3], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseInt(args[4], 10, 64)
			if err != nil {
				fmt.Println(err)
				continue
			}

			txHash, err := debugtool.CreateAndSendPDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy, uint64(amount))
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendPDETradeTransaction succeeded. TxHash: %v.\n", txHash)

		case "pdecontribute":
			if len(args) < 3 {
				fmt.Println("Not enough param for pdecontribute")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseInt(args[2], 10, 32)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID := common.PRVIDStr
			if len(args) > 3 {
				tokenID, err = ParseTokenID(args[3], tokenIDs)
				if err != nil {
					fmt.Println(err)
					continue
				}
			}

			txHash, err := debugtool.CreateAndSendPDEContributeTransaction(privateKey, "newpair", tokenID, uint64(amount))
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendPDEContributeTransaction for token %v succeeded. TxHash: %v.\n", tokenID, txHash)

		case "pdewithdraw":
			if len(args) < 5 {
				fmt.Println("Not enough param for pdewithdraw")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID1, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[3], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			sharedAmount, err := strconv.ParseInt(args[4], 10, 32)
			if err != nil {
				fmt.Println(err)
				continue
			}

			txHash, err := debugtool.CreateAndSendPDEWithdrawalTransaction(privateKey, tokenID1, tokenID2, uint64(sharedAmount))
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendPDEWithdrawalTransaction succeeded. TxHash: %v.\n", txHash)

		case "pdestate":
			var bHeight uint64
			var err error
			if len(args) > 1 {
				tmpHeight, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					fmt.Println("cannot get beacon height", err)
					continue
				}

				bHeight = uint64(tmpHeight)
			} else { //Get the latest state
				bestBlocks, err := debugtool.GetBestBlock()
				if err != nil {
					fmt.Println("cannot get best block", err)
					continue
				}

				bHeight = bestBlocks[-1]
			}

			currentState, err := debugtool.GetCurrentPDEState(bHeight)
			if err != nil {
				fmt.Println(err)
				continue
			}
			b, _ := json.MarshalIndent(currentState, "", "\t")
			fmt.Printf("Beacon Height: %v, state:\n%v\n", bHeight, string(b))

		case "poolpairs":
			var bHeight uint64
			var err error
			if len(args) > 1 {
				tmpHeight, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					fmt.Println("cannot get beacon height", err)
					continue
				}

				bHeight = uint64(tmpHeight)
			} else { //Get the latest state
				bestBlocks, err := debugtool.GetBestBlock()
				if err != nil {
					fmt.Println("cannot get best block", err)
					continue
				}

				bHeight = bestBlocks[-1]
			}

			allPoolPairs, err := debugtool.GetAllPDEPoolPairs(bHeight)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("There are %v pool pairs.\n", len(allPoolPairs))
			for _, value := range allPoolPairs {
				fmt.Printf("%v - %v: %v - %v\n", value.Token1IDStr, value.Token2IDStr, value.Token1PoolValue, value.Token2PoolValue)
			}

		case "pool":
			if len(args) < 3 {
				fmt.Println("need at least 3 arguments")
				continue
			}

			tokenID1, err := ParseTokenID(args[1], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			var bHeight uint64
			if len(args) > 3 {
				tmpHeight, err := strconv.ParseInt(args[3], 10, 32)
				if err != nil {
					fmt.Println("cannot get beacon height", err)
					continue
				}

				bHeight = uint64(tmpHeight)
			} else { //Get the latest state
				bestBlocks, err := debugtool.GetBestBlock()
				if err != nil {
					fmt.Println("cannot get best block", err)
					continue
				}

				bHeight = bestBlocks[-1]
			}

			poolPair, err := debugtool.GetPDEPoolPair(bHeight, tokenID1, tokenID2)
			if err != nil {
				if tokenID1 != common.PRVIDStr && tokenID2 != common.PRVIDStr {
					poolPair1, err := debugtool.GetPDEPoolPair(bHeight, tokenID1, common.PRVIDStr)
					if err != nil {
						fmt.Println(err)
						continue
					}
					poolPair2, err := debugtool.GetPDEPoolPair(bHeight, common.PRVIDStr, tokenID2)
					if err != nil {
						fmt.Println(err)
						continue
					}

					fmt.Println("Cross pool found:")
					fmt.Printf("Pool 1: %v - %v: %v - %v\n", poolPair1.Token1IDStr, poolPair1.Token2IDStr, poolPair1.Token1PoolValue, poolPair1.Token2PoolValue)
					fmt.Printf("Pool 2: %v - %v: %v - %v\n", poolPair2.Token1IDStr, poolPair2.Token2IDStr, poolPair2.Token1PoolValue, poolPair2.Token2PoolValue)
					continue
				} else {
					fmt.Println(err)
					continue
				}

			}

			fmt.Printf("%v - %v: %v - %v\n", poolPair.Token1IDStr, poolPair.Token2IDStr, poolPair.Token1PoolValue, poolPair.Token2PoolValue)

		case "tradevalue":
			if len(args) < 4 {
				fmt.Println("need at least 4 arguments")
				continue
			}

			tokenID1, err := ParseTokenID(args[1], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseInt(args[3], 10, 64)
			if err != nil {
				fmt.Println("cannot parse amount", args[3])
				continue
			}

			expectedTradeValue, err := debugtool.GetTradeValue(tokenID1, tokenID2, uint64(amount))
			if err != nil {
				if tokenID1 != common.PRVIDStr && tokenID2 != common.PRVIDStr {
					//Call cross pools trade
					expectedTradeValue, err = debugtool.GetXTradeValue(tokenID1, tokenID2, uint64(amount))
					if err != nil {
						fmt.Println(err)
						continue
					}
				} else {
					fmt.Println(err)
					continue
				}
			}

			rate := float64(expectedTradeValue) / float64(amount)
			fmt.Printf("Sell %v of token %v, get %v of token %v, rate %v, %v\n", amount, tokenID1, expectedTradeValue, tokenID2, rate, 1/rate)

		case "checkprice":
			if len(args) < 4 {
				fmt.Println("need at least 4 arguments")
				continue
			}

			tokenID1, err := ParseTokenID(args[1], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseInt(args[3], 10, 64)
			if err != nil {
				fmt.Println("cannot parse amount", args[3])
				continue
			}

			expectedTradeValue, err := debugtool.CheckXPrice(tokenID1, tokenID2, uint64(amount))
			if err != nil {
				fmt.Println(err)
				continue
			}

			rate := float64(expectedTradeValue) / float64(amount)
			fmt.Printf("Sell %v of token %v, get %v of token %v, rate %v, %v\n", amount, tokenID1, expectedTradeValue, tokenID2, rate, 1/rate)

		case "beststable":
			if len(args) < 2 {
				fmt.Println("not enough param for beststable")
			}

			amount, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID := common.PRVIDStr
			if len(args) > 2 {
				tokenID, err = ParseTokenID(args[2], tokenIDs)
				if err != nil {
					fmt.Println(err)
				}
			}

			token, value, err := debugtool.ChooseBestStableCoinPool(tokenID, uint64(amount))
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(token, value)

		//STAKING
		case "staking":
			if len(args) < 2 {
				fmt.Println("Not enough param for staking")
				continue
			}
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			autoStaking := true
			if len(args) > 2 {
				autoStaking, err = strconv.ParseBool(args[2])
				if err != nil {
					autoStaking = false
				}
			}

			var privateSeed string
			privateSeed, ok := privateSeeds[privateKey]
			if !ok {
				privateSeedBytes := privacy.HashToScalar([]byte(privateKey)).ToBytesS()
				privateSeed = base58.Base58Check{}.Encode(privateSeedBytes, common.ZeroByte)
				privateSeeds[privateKey] = privateSeed
				fmt.Println("privateSeed", privateSeed)
			}

			txHash, err := debugtool.CreateAndSendStakingTransaction(privateKey, privateSeed, "", "", autoStaking)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendStakingTransaction succeeded. TxHash: %v.\n", txHash)

		case "unstaking":
			if len(args) < 2 {
				fmt.Println("Not enough param for staking")
				continue
			}
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			var privateSeed string
			privateSeed, ok := privateSeeds[privateKey]
			if !ok {
				privateSeedBytes := privacy.HashToScalar([]byte(privateKey)).ToBytesS()
				privateSeed = base58.Base58Check{}.Encode(privateSeedBytes, common.ZeroByte)
				privateSeeds[privateKey] = privateSeed
			}

			candidateAddr := ""
			if len(args) > 2 {
				candidateAddr = args[2]
			}

			txHash, err := debugtool.CreateAndSendUnStakingTransaction(privateKey, privateSeed, candidateAddr)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendUnStakingTransaction succeeded. TxHash: %v.\n", txHash)

		case "reward":
			if len(args) < 2 {
				fmt.Println("Not enough param for staking")
				continue
			}
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			candidateAddr := ""
			if len(args) > 2 {
				candidateAddr = args[2]
			}

			txHash, err := debugtool.CreateAndSendWithDrawRewardTransaction(privateKey, candidateAddr)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendWithDrawRewardTransaction succeeded. TxHash: %v.\n", txHash)

		case "listreward":
			b, err := rpc.GetListRewardAmount()
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(string(b))

		//BRIDGE
		case "ethhash":
			if len(args) < 2 {
				fmt.Println("not enough arguments for ethhash")
			}
			txHash := args[1]
			var url = ""
			if len(args) > 2 {
				url = args[2]
			}

			b, err := debugtool.GetETHTxByHash(url, txHash)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println(b)

		case "ethblock":
			if len(args) < 2 {
				fmt.Println("not enough arguments for ethblock")
			}
			txHash := args[1]
			var url = ""
			if len(args) > 2 {
				url = args[2]
			}

			b, err := debugtool.GetETHBlockByHash(url, txHash)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println(b)

		case "ethreceipt":
			if len(args) < 2 {
				fmt.Println("not enough arguments for ethreceipt")
			}
			txHash := args[1]
			var url = ""
			if len(args) > 2 {
				url = args[2]
			}

			b, err := debugtool.GetETHTxReceipt(url, txHash)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println(b.BlockHash.String(), b.BlockNumber, b.TxHash.String())

		case "shield":
			if len(args) < 4 {
				fmt.Println("Not enough param for shield")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID, err := ParseTokenID(args[2], tokenIDs)
			if err != nil {
				fmt.Println(err)
				continue
			}

			ethTxHash := args[3]

			txHash, err := debugtool.CreateAndSendIssuingETHRequestTransaction(privateKey, ethTxHash, tokenID)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendIssuingETHRequestTransaction succeeded. TxHash: %v.\n", txHash)

		//GENERAL
		case "shard":
			activeShards, err := debugtool.GetActiveShard()
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println("Number of active shards:", activeShards)
			common.MaxShardNumber = activeShards

		case "dec58":
			b, _, err := base58.Base58Check{}.Decode(args[1])
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(b, string(b))

		case "gencan":
			for i := 0; i < 10; i++ {
				privateKey, _, _ := GenKeySet([]byte(fmt.Sprintf("can%v", i)))
				privateSeedBytes := privacy.HashToScalar([]byte(privateKey)).ToBytesS()
				privateSeed := base58.Base58Check{}.Encode(privateSeedBytes, common.ZeroByte)

				fmt.Printf("if [ \"$1\" == \"can%v\" ]; then\n", i)
				toBePrinted2 := fmt.Sprintf("./incognito --datadir \"data/staker%v\" --rpclisten \"0.0.0.0:%v\" --listen \"0.0.0.0:%v\" --miningkeys \"%v\" --discoverpeersaddress \"0.0.0.0:9330\" --externaladdress \"0.0.0.0:%v\" --norpcauth",
					i, 10335+i, 10452+i, privateSeed, 10452+i)
				fmt.Println(toBePrinted2)
				fmt.Println("fi")
			}

		//SECURE
		case "stransfer":
			if len(args) < 4 {
				fmt.Println("need at least 4 arguments.")
			}
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			paymentAddress, err := ParsePaymentAddress(args[2], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			amount, err := strconv.ParseUint(args[3], 10, 64)
			if err != nil {
				fmt.Println("cannot parse amount", args[3], len(args[3]))
				continue
			}

			var securityLevel = int64(2)
			if len(args) > 4 {
				securityLevel, err = strconv.ParseInt(args[4], 10, 64)
				if err != nil {
					fmt.Println(err)
					continue
				}
			}

			////Default version is 2
			//txVersion := int8(-1)
			//if len(args) > 4 {
			//	tmpVersion, err := strconv.ParseUint(args[4], 10, 32)
			//	if err != nil {
			//		fmt.Println("cannot parse version", err)
			//		continue
			//	}
			//	if tmpVersion > 2 {
			//		fmt.Println("version invalid", tmpVersion)
			//		continue
			//	}
			//	txVersion = int8(tmpVersion)
			//}

			txHash, err := debugtool.CreateAndSendRawSecureTransaction(privateKey, paymentAddress, amount, int(securityLevel))
			if err != nil {
				fmt.Println("CreateAndSendRawTransaction returns an error:", err)
				continue
			}

			fmt.Printf("CreateAndSendRawSecureTransaction succeeded. TxHash: %v.\n", txHash)
		default:
			fmt.Printf("cannot find command: %v\n", args[0])
			continue
		}

	}
}
