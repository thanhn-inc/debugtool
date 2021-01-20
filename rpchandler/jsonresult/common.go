package jsonresult

import "github.com/thanhn-inc/debugtool/common/base58"

func EncodeBase58Check(b []byte) string {
	if b == nil || len(b) == 0 {
		return ""
	}
	return base58.Base58Check{}.Encode(b, 0x0)
}
