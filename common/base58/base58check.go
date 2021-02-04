// Copyright (c) 2013-2014 The thaibaoautonomous developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58

import (
	"bytes"
	"errors"
	lru "github.com/hashicorp/golang-lru"
	"github.com/thanhn-inc/debugtool/common"
)

// ErrChecksum indicates that the checksum of a check-encoded string does not verify against
// the checksum.
var ErrChecksum = errors.New("checksum error")

// ErrInvalidFormat indicates that the check-encoded string has an invalid format.
var ErrInvalidFormat = errors.New("invalid format: version and/or checksum bytes missing")


// ChecksumFirst4Bytes receives data in bytes array
// and returns a checksum which is 4 first bytes of hashing of data.
//
// If isNewCheckSum, double SHA256 will be employed. Otherwise, single SHA3 will be employed.
func ChecksumFirst4Bytes(data []byte, isNewCheckSum bool) (ckSum []byte) {
	/*if len(data) == 0 {
		return []byte{}
	}*/
	ckSum = make([]byte, common.CheckSumLen)
	if !isNewCheckSum {
		h2 := common.HashB(data)
		copy(ckSum[:], h2[:4])
	} else {
		h2 := common.SHA256(common.SHA256(data))
		copy(ckSum[:], h2[:4])
	}
	return
}

type Base58Check struct {
}

var base58Cache, _ = lru.New(10000)

// Encode prepends a version byte and appends a four byte checksum.
func (self Base58Check) Encode(input []byte, version byte) string {
	/*if len(input) == 0 {
		return ""
	}*/
	value, exist := base58Cache.Get(string(input))
	if exist {
		return value.(string)
	}

	b := make([]byte, 0, 1+len(input)+common.CheckSumLen)
	b = append(b, version)
	b = append(b, input[:]...)
	cksum := ChecksumFirst4Bytes(b, version == 1)
	b = append(b, cksum[:]...)
	encodeData := Base58{}.Encode(b)
	base58Cache.Add(string(input), encodeData)
	return encodeData
}

// NewEncode prepends a version byte and appends a 4-byte checksum.
//
// New way to generate the 4-byte checksum is applied to this function.
func (self Base58Check) NewEncode(input []byte, version byte) string {
	/*if len(input) == 0 {
		return ""
	}*/
	value, exist := base58Cache.Get(string(input))
	if exist {
		return value.(string)
	}

	b := make([]byte, 0, 1+len(input)+common.CheckSumLen)
	b = append(b, version)
	b = append(b, input[:]...)
	cksum := ChecksumFirst4Bytes(b, true)
	b = append(b, cksum[:]...)
	encodeData := Base58{}.Encode(b)
	base58Cache.Add(string(input), encodeData)
	return encodeData
}

// Decode decodes a string that was encoded with Encode and verifies the checksum.
//
// The Decode function allows to decode both old and new base58-encoded strings.
func (self Base58Check) Decode(input string) (result []byte, version byte, err error) {
	/*if len(input) == 0 {
		return []byte{}, 0, errors.New("Input to decode is empty")
	}*/

	decoded := Base58{}.Decode(input)
	if len(decoded) < 5 {
		return nil, 0, ErrInvalidFormat
	}
	version = decoded[0]
	// var cksum []byte
	cksum := make([]byte, common.CheckSumLen)
	copy(cksum[:], decoded[len(decoded)-common.CheckSumLen:])
	if bytes.Compare(ChecksumFirst4Bytes(decoded[:len(decoded)-common.CheckSumLen], true), cksum) != 0 { //Try to decode with the new checksum
		if bytes.Compare(ChecksumFirst4Bytes(decoded[:len(decoded)-common.CheckSumLen], false), cksum) != 0 { //Try to decode with the old checksum
			return nil, 0, ErrChecksum
		}
	}
	payload := decoded[1 : len(decoded)-common.CheckSumLen]
	result = append(result, payload...)
	return
}

var b58Check = Base58Check{}

func DecodeCheck(input string) (result []byte, version byte, err error) {
	return b58Check.Decode(input)
}

func EncodeCheck(input []byte) string {
	return b58Check.Encode(input, 0x00)
}
