package common

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"math/big"
)

// GetShardIDFromLastByte receives a last byte of public key and
// returns a corresponding shardID
func GetShardIDFromLastByte(b byte) byte {
	return byte(int(b) % MaxShardNumber)
}

// RandBigIntMaxRange generates a big int with maximum value
func RandBigIntMaxRange(max *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, max)
}

// RandBytes generates random bytes with length
func RandBytes(length int) []byte {
	rbytes := make([]byte, length)
	rand.Read(rbytes)
	return rbytes
}


// CompareStringArray receives 2 arrays of string
// and check whether 2 arrays is the same or not
func CompareStringArray(src []string, dst []string) bool {
	if len(src) != len(dst) {
		return false
	}
	for idx, val := range src {
		if dst[idx] != val {
			return false
		}
	}
	return true
}

// BytesToInt32 converts little endian 4-byte array to int32 number
func BytesToInt32(b []byte) (int32, error) {
	if len(b) != Int32Size {
		return 0, errors.New("invalid length of input BytesToInt32")
	}

	return int32(binary.LittleEndian.Uint32(b)), nil
}

// Int32ToBytes converts int32 number to little endian 4-byte array
func Int32ToBytes(value int32) []byte {
	b := make([]byte, Int32Size)
	binary.LittleEndian.PutUint32(b, uint32(value))
	return b
}

// IntToBytes converts an integer number to 2-byte array in big endian
func IntToBytes(n int) []byte {
	if n == 0 {
		return []byte{0, 0}
	}

	a := big.NewInt(int64(n))

	if len(a.Bytes()) > 2 {
		return []byte{}
	}

	if len(a.Bytes()) == 1 {
		return []byte{0, a.Bytes()[0]}
	}

	return a.Bytes()
}

// BytesToInt reverts an integer number from 2-byte array
func BytesToInt(bytesArr []byte) int {
	if len(bytesArr) != 2 {
		return 0
	}

	numInt := new(big.Int).SetBytes(bytesArr)
	return int(numInt.Int64())
}

// BytesToUint32 converts big endian 4-byte array to uint32 number
func BytesToUint32(b []byte) (uint32, error) {
	if len(b) != Uint32Size {
		return 0, errors.New("invalid length of input BytesToUint32")
	}
	return binary.BigEndian.Uint32(b), nil
}

// Uint32ToBytes converts uint32 number to big endian 4-byte array
func Uint32ToBytes(value uint32) []byte {
	b := make([]byte, Uint32Size)
	binary.BigEndian.PutUint32(b, value)
	return b
}

// BytesToUint64 converts little endian 8-byte array to uint64 number
func BytesToUint64(b []byte) (uint64, error) {
	if len(b) != Uint64Size {
		return 0, errors.New("invalid length of input BytesToUint64")
	}
	return binary.LittleEndian.Uint64(b), nil
}

// Uint64ToBytes converts uint64 number to little endian 8-byte array
func Uint64ToBytes(value uint64) []byte {
	b := make([]byte, Uint64Size)
	binary.LittleEndian.PutUint64(b, value)
	return b
}

// Int64ToBytes converts int64 number to little endian 8-byte array
func Int64ToBytes(value int64) []byte {
	return Uint64ToBytes(uint64(value))
}

// BoolToByte receives a value in bool
// and returns a value in byte
func BoolToByte(value bool) byte {
	var bitSetVar byte
	if value {
		bitSetVar = 1
	}
	return bitSetVar
}

// AddPaddingBigInt adds padding to big int to it is fixed size
// and returns bytes array
func AddPaddingBigInt(numInt *big.Int, fixedSize int) []byte {
	numBytes := numInt.Bytes()
	lenNumBytes := len(numBytes)
	zeroBytes := make([]byte, fixedSize-lenNumBytes)
	numBytes = append(zeroBytes, numBytes...)
	return numBytes
}

// AppendSliceString is a variadic function,
// receives some lists of array of strings
// and appends them to one list of array of strings
func AppendSliceString(arrayStrings ...[][]string) [][]string {
	res := [][]string{}
	for _, arrayString := range arrayStrings {
		res = append(res, arrayString...)
	}
	return res
}

func Uint16ToBytes(v uint16) [2]byte {
	var res [2]byte
	res[0] = uint8(v >> 8)
	res[1] = uint8(v & 0xff)
	return res
}

func BytesToUint16(b [2]byte) uint16 {
	return uint16(b[0])<<8 + uint16(b[1])
}

func BytesSToUint16(b []byte) (uint16, error) {
	if len(b) != 2 {
		return 0, errors.New("Cannot convert BytesSToUint16: length of byte is not 2")
	}
	var bytes [2]byte
	copy(bytes[:], b[:2])
	return BytesToUint16(bytes), nil
}

// Has0xPrefix validates str begins with '0x' or '0X'.
func Has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// Hex2Bytes returns the bytes represented by the hexadecimal string str.
func Hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)
	return h
}

// FromHex returns the bytes represented by the hexadecimal string s.
// s may be prefixed with "0x".
func FromHex(s string) []byte {
	if Has0xPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return Hex2Bytes(s)
}

// HexToHash sets byte representation of s to hash.
// If b is larger than len(h), b will be cropped from the left.
func HexToHash(s string) Hash { return BytesToHash(FromHex(s)) }

// B2I convert byte array to big int which belong to Fp
func B2I(bytes []byte) *big.Int {
	res := big.NewInt(0)
	res.SetBytes(bytes)
	for res.Cmp(bn256.Order) != -1 {
		bytes = Hash4Bls(bytes)
		res.SetBytes(bytes)
	}
	return res
}

// B2ImN is Bytes to Int mod N, with N is secp256k1 curve order
func B2ImN(bytes []byte) *big.Int {
	x := big.NewInt(0)
	x.SetBytes(ethcrypto.Keccak256Hash(bytes).Bytes())
	for x.Cmp(ethcrypto.S256().Params().N) != -1 {
		x.SetBytes(ethcrypto.Keccak256Hash(x.Bytes()).Bytes())
	}
	return x
}
