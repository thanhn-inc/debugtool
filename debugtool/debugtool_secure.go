package debugtool

import (
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/wallet"
	"time"
)

func CreateAndSendRawSecureTransaction(privateKey string, addr string, amount uint64, securityLevel int) ([]string, error) {
	var txList []string

	currentPrivateKey := privateKey
	amount = amount + uint64(securityLevel) * DefaultPRVFee
	var nextPrivateKey string
	var nextReceiver string

	pkSender := PrivateKeyToPublicKey(privateKey)
	targetShardID := common.GetShardIDFromLastByte(pkSender[len(pkSender) - 1])

	//Create intermediate addresses
	for i := 0; i < securityLevel; i++ {
		var nextWallet *wallet.KeyWallet
		var err error
		idx := 0

		for {
			nextWallet, err = wallet.NewMasterKey(privacy.HashToScalar([]byte(currentPrivateKey + string(securityLevel) + string(idx))).ToBytesS())
			if err != nil {
				fmt.Println("NewMasterKey error:", err)
				return txList, err
			}

			nextPk := nextWallet.KeySet.PaymentAddress.Pk
			shardID := common.GetShardIDFromLastByte(nextPk[len(nextPk) - 1])
			if shardID != targetShardID {
				idx += 1
			} else {
				break
			}
		}

		nextPrivateKey = nextWallet.Base58CheckSerialize(wallet.PriKeyType)
		nextReceiver = nextWallet.Base58CheckSerialize(wallet.PaymentAddressType)

		fmt.Println("nextPrivateKey", nextPrivateKey)

		txHash, err := CreateAndSendRawTransaction(currentPrivateKey, []string{nextReceiver}, []uint64{amount}, -1, nil)
		if err != nil {
			fmt.Println("txList", txList)
			return txList, err
		}

		fmt.Printf("transfer %v from %v to %v: %v\n", amount, currentPrivateKey, nextReceiver, txHash)
		txList = append(txList, txHash)

		fmt.Printf("Checking if tx %v is in block...\n", txHash)

		start := time.Now()

		for {
			isInBlock, err := CheckTxInBlock(txHash)
			if err != nil {
				fmt.Println("txList", txList)
				return txList, err
			}
			if !isInBlock {
				fmt.Println("sleeping 10 seconds")
				time.Sleep(10 * time.Second)
				continue
			} else {
				fmt.Printf("tx %v is in block. Start checking balance of %v ...\n", txHash, nextPrivateKey)
				for {
					balance, err := GetBalance(nextPrivateKey, common.PRVIDStr)
					if err != nil {
						fmt.Println("getBalance error. TxList:", txList)
						return txList, err
					}
					if balance != 0 {
						fmt.Println("balance updated:", balance)
						break
					}
					elapsed := time.Since(start)
					if elapsed.Seconds() > 600 {
						fmt.Printf("Abort because timeOut. NextPrivateKey: %v, txList: %v\n", nextPrivateKey, txList)
						return txList, nil
					}
					fmt.Println("sleeping 10 seconds for balance...")
					time.Sleep(10 * time.Second)
				}
				break
			}
		}

		currentPrivateKey = nextPrivateKey
		amount -= DefaultPRVFee
	}

	//transfer to the real receiver
	nextReceiver = addr

	txHash, err := CreateAndSendRawTransaction(currentPrivateKey, []string{nextReceiver}, []uint64{amount}, -1, nil)
	if err != nil {
		fmt.Println("txList", txList)
		return txList, err
	}

	fmt.Printf("transfer %v from %v to %v: %v\n", amount, currentPrivateKey, nextReceiver, txHash)
	txList = append(txList, txHash)

	return txList, nil
}
