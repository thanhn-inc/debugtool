package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/debugtool"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"math/big"
	"os"
	"strconv"
	"strings"
)

//Comment the init function in blockchain/constants.go to run the debug tool.
func main() {
	//These variables are used for dev-debug purposes only.
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


	err := InitTestNet()
	if err != nil {
		panic(err)
	}

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
			err = SwitchPort(args[1])
			if err != nil {
				panic(err)
			}

		case "inittestnet":
			err = InitTestNet()
			if err != nil {
				panic(err)
			}

		case "initdevnet":
			port := ""
			if len(args) > 1 {
				port = args[1]
			}
			err = InitDevNet(port)
			if err != nil {
				panic(err)
			}

		case "initmainnet":
			err = InitMainNet()
			if err != nil {
				panic(err)
			}

		case "initlocal":
			port := "9334"
			if len(args) > 1 {
				port = args[1]
			}
			err = InitLocal(port)
			if err != nil {
				panic(err)
			}

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
			if len(args) < 2 {
				fmt.Println("not enough param for outcoin")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			var bHeight uint64
			if len(args) > 2 {
				tmpHeight, err := strconv.ParseInt(args[2], 10, 32)
				if err != nil {
					fmt.Println("cannot get beacon height", err)
					continue
				}

				bHeight = uint64(tmpHeight)
			} else { //retrieve from the beginning
				bHeight = uint64(0)
			}

			GetTXOs(privateKey, common.PRVIDStr, bHeight)

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

			tokenID := common.PRVIDStr
			if len(args) > 2 { //Check balance token
				tokenID, err = ParseTokenID(args[2])
				if err != nil {
					fmt.Println(err)
					continue
				}
			}

			balance, err := debugtool.GetBalance(privateKey, tokenID)
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
				tokenID, err = ParseTokenID(args[2])
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

			GetUTXOs(privateKey, tokenID, bi.Uint64())

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
				tokenID, err = ParseTokenID(args[2])
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

			tokenID, err := ParseTokenID(args[3])
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

		case "outtoken":
			if len(args) < 3 {
				fmt.Println("not enough param for outtoken")
				continue
			}

			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID, err := ParseTokenID(args[2])
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
			} else { //retrieve from the beginning
				bHeight = uint64(0)
			}

			GetTXOs(privateKey, tokenID, bHeight)

		case "listtoken":
			ListTokens()

		case "bridgetoken":
			ListBridgeTokens()

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
			if len(args) > 2 {
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

		case "ota":
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

			privateOTAKey := debugtool.PrivateKeyToPrivateOTAKey(privateKey)
			fmt.Println("PrivateOTA Key", privateOTAKey)

		case "genkeyset":
			privateKey, payment, _ := GenKeySet([]byte(args[1]))
			fmt.Println(privateKey, payment)

		case "cmkey":
			if len(args) < 2 {
				fmt.Printf("not enough param for %v\n", args[1])
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
				fmt.Println("privateSeed", privateSeed)
			}

			cmKey, err := GenerateCommitteeKey(privateKey, privateSeed)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(cmKey)

		case "sub":
			privateKey, err := ParsePrivateKey(args[1], privateKeys)
			if err != nil {
				fmt.Println(err)
				continue
			}

			b, err := rpc.SubmitKey(privateKey)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println(string(b))

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
			if len(args) > 1 {
				for {
					GetRawMempool()
					time.Sleep(5 * time.Second)
					fmt.Println("")
				}
			} else {
				GetRawMempool()
			}

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

			tokenID, err := ParseTokenID(args[2])
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

			tokenIDToSell, err := ParseTokenID(args[2])
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenIDToBuy, err := ParseTokenID(args[3])
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

			amount, err := strconv.ParseInt(args[2], 10, 64)
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID := common.PRVIDStr
			if len(args) > 3 {
				tokenID, err = ParseTokenID(args[3])
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

			tokenID1, err := ParseTokenID(args[2])
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[3])
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

			tokenID1, err := ParseTokenID(args[1])
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[2])
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

			tokenID1, err := ParseTokenID(args[1])
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[2])
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

			tokenID1, err := ParseTokenID(args[1])
			if err != nil {
				fmt.Println(err)
				continue
			}

			tokenID2, err := ParseTokenID(args[2])
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
				tokenID, err = ParseTokenID(args[2])
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

		case "tradestatus":
			if len(args) < 2 {
				fmt.Println("not enough param for beststable")
			}

			b, err := rpc.CheckTradeStatus(args[1])
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(string(b))

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

			tokenID, err := ParseTokenID(args[2])
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
