package debugtool

import (
	"errors"
	"fmt"
	"math/big"
	"time"
)

func UniswapValue(sellAmount, sellPoolAmount, buyPoolAmount uint64) (uint64, error) {
	invariant := big.NewInt(0)
	invariant.Mul(new(big.Int).SetUint64(sellPoolAmount), new(big.Int).SetUint64(buyPoolAmount))

	newSellPoolAmount := big.NewInt(0)
	newSellPoolAmount.Add(new(big.Int).SetUint64(sellPoolAmount), new(big.Int).SetUint64(sellAmount))

	newBuyPoolAmount := big.NewInt(0).Div(invariant, newSellPoolAmount).Uint64()
	modValue := big.NewInt(0).Mod(invariant, newSellPoolAmount)
	if modValue.Cmp(big.NewInt(0)) != 0 {
		newBuyPoolAmount++
	}
	if buyPoolAmount <= newBuyPoolAmount {
		return 0, errors.New(fmt.Sprintf("cannot calculate trade value: new pool (%v) is greater than oldPool (%v)", newBuyPoolAmount, buyPoolAmount))
	}

	return buyPoolAmount - newBuyPoolAmount, nil
}

//Choose best pool to trade something to stable coins
func ChooseBestStableCoinPool(tokenIDToSell string, sellAmount uint64) (string, uint64, error) {
	tokenIDs := []string{
		"716fd1009e2a1669caacc36891e707bfdf02590f96ebd897548e8963c95ebac0",
		"1ff2da446abfebea3ba30385e2ca99b0f0bbeda5c6371f4c23c939672b429a42",
		"3f89c75324b46f13c7b036871060e641d996a24c09b3065835cb1d38b799d6c1",
	}

	tokenToTrade := tokenIDs[0]
	maxValue := uint64(0)
	for i, tokenID := range tokenIDs {
		expectedTradeValue, err := CheckXPrice(tokenIDToSell, tokenID, sellAmount)
		if err != nil {
			return "", 0, err
		}
		if i <= 1{
			expectedTradeValue = expectedTradeValue * 1000
		}

		rate := float64(expectedTradeValue) / float64(sellAmount)

		fmt.Printf("trade %v %v ==> get %v %v ==> rate %v\n", sellAmount, tokenIDToSell, expectedTradeValue, tokenID, rate)
		if expectedTradeValue > maxValue {
			maxValue = expectedTradeValue
			tokenToTrade = tokenID
		}
	}

	return tokenToTrade, maxValue, nil
}

//Auto create and send a PDE trade transaction when expected rate is met
func AutoTrade(privateKey, tokenToSell, tokenToBuy string, amount uint64, expectedRate float64) (string, error) {
	balance, err := GetBalance(privateKey, tokenToSell)
	if err != nil {
		return "", nil
	}

	if balance < amount {
		return "", fmt.Errorf("balance insufficient: need %v, have %v", amount, balance)
	}

	for {
		expectedReceive, err := CheckXPrice(tokenToSell, tokenToBuy, amount)
		if err != nil {
			return "", err
		}

		rate := float64(expectedReceive)/ float64(amount)
		fmt.Printf("trade %v of %v ==> get %v of %v ==> rate: %v, expected rate: %v\n", amount, tokenToSell, expectedReceive, tokenToBuy, rate, expectedRate)
		if rate >= expectedRate {
			return CreateAndSendPDETradeTransaction(privateKey, tokenToSell, tokenToBuy, amount)
		} else {
			fmt.Println("Sleep 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}
}