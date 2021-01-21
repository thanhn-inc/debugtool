package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/debugtool"
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
	rpchandler.Server = new(rpchandler.RPCServer).InitLocal(newPort)
}
func GetShardIDFromPrivateKey(privateKey string) byte {
	pubkey := privateKeyToPublicKey(privateKey)
	return common.GetShardIDFromLastByte(pubkey[len(pubkey)-1])
}

//Keys
func privateKeyToPaymentAddress(privkey string, keyType int) string {
	keyWallet, _ := wallet.Base58CheckDeserialize(privkey)
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	paymentAddStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	switch  keyType {
	case 0: //Old address, old encoding
		addr, _ := wallet.GetPaymentAddressV1(paymentAddStr, false)
		return addr
	case 1:
		addr, _ := wallet.GetPaymentAddressV1(paymentAddStr, true)
		return addr
	default:
		return paymentAddStr
	}
}
func privateKeyToPublicKey(privkey string) []byte {
	keyWallet, err := wallet.Base58CheckDeserialize(privkey)
	if err != nil {
		panic(err)
	}
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	return keyWallet.KeySet.PaymentAddress.Pk
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
	if err != nil{
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

	for _, unspentCoin := range listUnspentCoins{
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
func GetPDEState(beaconHeight int64) {
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
	}

	tokenIDs := make(map[string]string)
	tokenIDs["USDT"] = "716fd1009e2a1669caacc36891e707bfdf02590f96ebd897548e8963c95ebac0"
	tokenIDs["BNB"] = "b2655152784e8639fa19521a7035f331eea1f1e911b2f3200a507ebb4554387b"
	tokenIDs["ETH"] = "ffd8d42dc40a8d166ea4848baf8b5f6e912ad79875f4373070b59392b1756c8f"
	tokenIDs["USDC"] = "1ff2da446abfebea3ba30385e2ca99b0f0bbeda5c6371f4c23c939672b429a42"
	tokenIDs["XMR"] = "c01e7dc1d1aba995c19b257412340b057f8ad1482ccb6a9bb0adce61afbf05d4"
	tokenIDs["BTC"] = "b832e5d3b1f01a4f0623f7fe91d6673461e1f5d37d91fe78c5c2e6183ff39696"
	tokenIDs["PRV"] = common.PRVIDStr

	rpchandler.Server = new(rpchandler.RPCServer).InitLocal("9334")
	//rpchandler.Server = new(rpchandler.RPCServer).InitTestnet()

	//tool := new(rpchandler.RPCServer).InitLocal("9334")
	//tool := new(rpchandler.RPCServer).InitMainnet()
	//tool := new(rpchandler.RPCServer).InitDevNet()
	//tool := new(rpchandler.RPCServer).InitTestnet()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter your choice (arguments separated by ONLY ONE space) and hit ENTER: ")
		text, _ := reader.ReadString('\n')
		args := strings.Split(text[:len(text)-1], " ")
		if len(args) < 1 {
			return
		}

		//Init network
		if args[0] == "port" {
			SwitchPort(args[1])
			fmt.Printf("New target: %v-%v\n", args[0], rpchandler.Server.GetURL())
		}
		if args[0] == "inittestnet" {
			rpchandler.Server = new(rpchandler.RPCServer).InitTestnet()
			fmt.Printf("New target: %v-%v\n", args[0], rpchandler.Server.GetURL())
		}
		if args[0] == "initdevnet" {
			rpchandler.Server = new(rpchandler.RPCServer).InitDevNet()
			fmt.Printf("New target: %v-%v\n", args[0], rpchandler.Server.GetURL())
		}
		if args[0] == "initmainnet" {
			rpchandler.Server = new(rpchandler.RPCServer).InitMainnet()
			fmt.Printf("New target: %v-%v\n", args[0], rpchandler.Server.GetURL())
		}
		if args[0] == "initlocal" {
			rpchandler.Server = new(rpchandler.RPCServer).InitLocal(args[1])
			fmt.Printf("New target: %v-%v\n", args[0], rpchandler.Server.GetURL())
		}

		//PRV RPCs
		if args[0] == "send" {
			sendTx()
		}
		if args[0] == "outcoin" {
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
		}
		if args[0] == "balance" {
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

			balance, err := debugtool.GetBalance(privateKey, common.PRVIDStr)
			if err != nil{
				fmt.Println(err)
				continue
			}
			fmt.Println("Balance =", balance)
		}
		if args[0] == "transfer" {
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

			var paymentAddress string
			if len(args[2]) < 4 {
				index, err := strconv.ParseInt(args[2], 10, 32)
				if err != nil {
					fmt.Println(err)
					panic(err)
				}
				if index >= int64(len(privateKeys)) {
					fmt.Println("Cannot find the private key")
					continue
				}
				paymentAddress = privateKeyToPaymentAddress(privateKeys[index], -1)
			} else {
				paymentAddress = args[2]
			}

			amount, err := strconv.ParseInt(args[3], 10, 32)
			if err != nil {
				fmt.Println("cannot parse amount", args[3])
				continue
			}

			txHash, err := debugtool.CreateAndSendRawTransaction(privateKey, []string{paymentAddress}, []uint64{uint64(amount)}, 1, nil)
			if err != nil {
				fmt.Println("CreateAndSendRawTransaction returns an error:", err)
				continue
			}

			fmt.Printf("CreateAndSendRawTransaction succeeded. TxHash: %v.\n", txHash)
		}
		if args[0] == "uot" {
			if len(args) < 2 {
				fmt.Println("Not enough param for unspentouttoken")
				continue
			}
			tokenID := common.PRVIDStr
			if len(args) > 2 {
				tokenID = args[2]
				if len(args[2]) < 10 {
					tokenID = tokenIDs[args[2]] //Make sure you have the right token name
				}
			}

			var privateKey string
			if len(args[1]) < 3 {
				index, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					fmt.Println(err)
					continue
				}
				privateKey = privateKeys[index]
			} else {
				privateKey = args[1]
			}
			bi := big.NewInt(0)
			if len(args) >= 4 {
				_, ok := bi.SetString(args[3], 10)
				if !ok {
					continue
				}
			}

			GetUnspentOutputToken(privateKey, tokenID, bi.Uint64())
		}


		//TOKEN RPCs
		if args[0] == "inittoken" {
			if len(args) < 3 {
				fmt.Println("need at least 3 arguments.")
				continue
			}

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

			b, err := rpc.CreateAndSendPrivacyCustomTokenTransaction(privateKey, args[2])
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(string(b))
		}
		if args[0] == "balancetoken" {
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

			var tokenID = args[2]
			var ok bool
			if len(tokenID) < 10 {
				tokenID, ok = tokenIDs[tokenID]
				if !ok {
					fmt.Println("cannot find tokenID")
					fmt.Println("list of tokenIDs", tokenIDs)
					continue
				}
			}

			balance, err := debugtool.GetBalance(privateKey, tokenID)
			if err != nil{
				fmt.Println(err)
				continue
			}
			fmt.Println("Balance =", balance)
		}
		if args[0] == "transfertoken" {
			if len(args) < 5 {
				fmt.Println("need at least 5 arguments.")
			}

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

			var paymentAddress string
			if len(args[2]) < 4 {
				index, err := strconv.ParseInt(args[2], 10, 32)
				if err != nil {
					fmt.Println(err)
					panic(err)
				}
				if index >= int64(len(privateKeys)) {
					fmt.Println("Cannot find the private key")
					continue
				}
				paymentAddress = privateKeyToPaymentAddress(privateKeys[index], -1)
			} else {
				paymentAddress = args[2]
			}

			var tokenID = args[3]
			var ok bool
			if len(tokenID) < 10 {
				tokenID, ok = tokenIDs[tokenID]
				if !ok {
					fmt.Println("cannot find tokenID")
					fmt.Println("list of tokenIDs", tokenIDs)
					continue
				}
			}

			amount, err := strconv.ParseInt(args[4], 10, 32)
			if err != nil {
				fmt.Println("cannot parse amount", args[4])
				continue
			}

			txHash, err := debugtool.CreateAndSendRawTokenTransaction(privateKey, []string{paymentAddress}, []uint64{uint64(amount)}, 1, tokenID, 1)
			if err != nil {
				fmt.Println("CreateAndSendRawTokenTransaction returns an error:", err)
				continue
			}

			fmt.Printf("CreateAndSendRawTokenTransaction succeeded. TxHash: %v.\n", txHash)
		}
		if args[0] == "listtoken" {
			ListTokens()
		}

		//Keys
		if args[0] == "payment" {
			var err error
			if len (args) < 2{
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
			fmt.Println("Payment Address", privateKeyToPaymentAddress(privateKey, int(keyType)))
		}
		if args[0] == "public" {
			fmt.Println("Public Key", privateKeyToPublicKey(args[1]))
		}
		if args[0] == "genkeyset" {
			privateKey, payment, _ := GenKeySet([]byte(args[1]))
			fmt.Println(privateKey, payment)
		}

		//Blockchain
		if args[0] == "info" {
			GetBlockchainInfo()
		}
		if args[0] == "beaconstate" {
			GetBeaconBestState()
		}
		if args[0] == "bestblock" {
			GetBestBlock()
		}
		if args[0] == "mempool" {
			GetRawMempool()
		}
		if args[0] == "txhash" {
			GetTxByHash(args[1])
		}

		//PDEX
		if args[0] == "pdetradeprv" {
			if len(args) < 4 {
				fmt.Println("Not enough param for pdetradeprv")
				continue
			}

			privateKey := args[1]
			if len(args[1]) < 3 {
				index, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					panic(err)
				}
				privateKey = privateKeys[index]
			}

			tokenID := args[2]
			if len(args[2]) < 10 {
				tokenID = tokenIDs[args[2]]
			}

			amount, err := strconv.ParseInt(args[3], 10, 32)
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
		}
		if args[0] == "pdecontribute" {
			if len(args) < 3 {
				fmt.Println("Not enough param for pdetradeprv")
				continue
			}

			privateKey := args[1]
			if len(args[1]) < 3 {
				index, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					panic(err)
				}
				privateKey = privateKeys[index]
			}

			amount, err := strconv.ParseInt(args[2], 10, 32)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID := common.PRVIDStr
			if len(args) > 3 {
				tokenID = args[3]
				if len(tokenID) < 10 {
					tokenID = tokenIDs[tokenID]
				}
			}

			txHash, err := debugtool.CreateAndSendPDEContributeTransaction(privateKey, "newpair", tokenID, uint64(amount))
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("CreateAndSendPDEContributeTransaction for token %v succeeded. TxHash: %v.\n", tokenID, txHash)
		}
		if args[0] == "pdewithdraw" {
			if len(args) < 5 {
				fmt.Println("Not enough param for pdetradeprv")
				continue
			}

			privateKey := args[1]
			if len(args[1]) < 3 {
				index, err := strconv.ParseInt(args[1], 10, 32)
				if err != nil {
					panic(err)
				}
				privateKey = privateKeys[index]
			}

			tokenID1 := args[2]
			if len(tokenID1) < 10 {
				tmpTokenID, ok := tokenIDs[tokenID1]
				if !ok {
					fmt.Println("tokenID not found")
				}
				tokenID1 = tmpTokenID
			}

			tokenID2 := args[3]
			if len(tokenID2) < 10 {
				tmpTokenID, ok := tokenIDs[tokenID2]
				if !ok {
					fmt.Println("tokenID not found")
				}
				tokenID2 = tmpTokenID
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
		}
		if args[0] == "pdestate" {
			if len(args) < 2 {
				fmt.Println("need at least 2 arguments")
				continue
			}
			bHeight, err := strconv.ParseInt(args[1], 10, 32)
			if err != nil {
				fmt.Println("cannot get beacon height")
				continue
			}

			GetPDEState(bHeight)
		}


		//General
		if args[0] == "shard" {
			activeShards, err := debugtool.GetActiveShard()
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println("Number of active shards:", activeShards)
			common.MaxShardNumber = activeShards
		}

		if args[0] == "dec58" {
			b, _, err := base58.Base58Check{}.Decode(args[1])
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(b)
		}
	}
}