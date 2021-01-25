package debugtool

import (
	"errors"
	"fmt"
	"math/big"
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
