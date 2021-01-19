package base58

import (
	"fmt"
	"testing"
)

func TestNewAlphabet(t *testing.T) {
	fmt.Println(BTCAlphabet.encode)
	fmt.Println(BTCAlphabet.decode)

	msg := []byte("Ahihihihihih")

	fmt.Println(FastBase58Encoding(msg))

	fmt.Println(ChecksumFirst4Bytes(msg, true))
	fmt.Println(ChecksumFirst4Bytes(msg, false))
}

