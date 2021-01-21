package rpc

import (
	"fmt"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/wallet"
)

func GetListRewardAmount() ([]byte, error){
	query := fmt.Sprintf(`{
			"id": 1,
			"jsonrpc": "1.0",
			"method": "listrewardamount",
			"params": [
			]
	}`)

	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func Stake(privKey string, seed string) ([]byte, error) {
	keyWallet, _ := wallet.Base58CheckDeserialize(privKey)
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	paymentAddStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	paymentAddStr, _ = wallet.GetPaymentAddressV1(paymentAddStr, false)
	query := fmt.Sprintf(`{
	  "jsonrpc":"1.0",
	  "method":"createandsendstakingtransaction",
	  "params":[
			"%s",
			{
				"12RxahVABnAVCGP3LGwCn8jkQxgw7z1x14wztHzn455TTVpi1wBq9YGwkRMQg3J4e657AbAnCvYCJSdA9czBUNuCKwGSRQt55Xwz8WA": 1750000000000
			},
			5,
			0,
			{
				"StakingType": 63,
				"CandidatePaymentAddress": "%s",
				"PrivateSeed": "%s",
				"RewardReceiverPaymentAddress": "%s",
				"AutoReStaking": true
			}
	  ],
	  "id":1
	}`, privKey, paymentAddStr, seed, paymentAddStr)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func Unstake(privKey string, seed string) ([]byte, error) {
	//private key [4]
	//wrongPrivKey := "112t8rnXWRThUTJQgoyH6evV8w19dFZfKWpCh8rZpfymW9JTgKPEVQS44nDRPpsooJiGStHxu81m3HA84t9DBVobz8hgBKRMcz2hddPWNX9N"
	keyWallet, _ := wallet.Base58CheckDeserialize(privKey)
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	paymentAddStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	//paymentAddStr, _ = wallet.GetPaymentAddressV1(paymentAddStr, false)
	query := fmt.Sprintf(`{
		"id":1,
		"jsonrpc":"1.0",
		"method":"createandsendstopautostakingtransaction",
		"params": [
			"%s",
			{
				"12RxahVABnAVCGP3LGwCn8jkQxgw7z1x14wztHzn455TTVpi1wBq9YGwkRMQg3J4e657AbAnCvYCJSdA9czBUNuCKwGSRQt55Xwz8WA": 0
			},
			10,
			0,
			{
				"StopAutoStakingType" : 127,
				"CandidatePaymentAddress" : "%s",
				"PrivateSeed":"%s"
			}
		]
	}`, privKey, paymentAddStr, seed)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}

func WithdrawReward(privKey string, tokenID string) ([]byte, error) {
	keyWallet, _ := wallet.Base58CheckDeserialize(privKey)
	keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	paymentAddStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	paymentAddStr, _ = wallet.GetPaymentAddressV1(paymentAddStr, false)
	query := fmt.Sprintf(`{
    "jsonrpc": "1.0",
    "method": "withdrawreward",
    "params": [
        "%s",
        {},
		10,
		0,
        {
            "PaymentAddress": "%s",
            "TokenID": "%s"
        }
    ],
    "id": 1
	}`, privKey, paymentAddStr, tokenID)
	return rpchandler.Server.SendPostRequestWithQuery(query)
}
