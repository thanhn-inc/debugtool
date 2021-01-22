package jsonresult

import (
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
)

type RandomCommitmentAndPublicKeyResult struct {
	CommitmentIndices   []uint64 `json:"CommitmentIndices"`
	PublicKeys 			[]string `json:"PublicKeys"`
	Commitments         []string `json:"Commitments"`
	AssetTags	        []string `json:"AssetTags"`
}

func NewRandomCommitmentAndPublicKeyResult(commitmentIndices []uint64, publicKeys, commitments, assetTags [][]byte) *RandomCommitmentAndPublicKeyResult {
	result := &RandomCommitmentAndPublicKeyResult{
		CommitmentIndices:   commitmentIndices,
	}
	tempCommitments := make([]string, 0)
	for _, commitment := range commitments {
		tempCommitments = append(tempCommitments, base58.Base58Check{}.Encode(commitment, common.ZeroByte))
	}
	result.Commitments = tempCommitments

	tempPublicKeys := make([]string, 0)
	for _, pubkey := range publicKeys {
		tempPublicKeys = append(tempPublicKeys, base58.Base58Check{}.Encode(pubkey, common.ZeroByte))
	}
	result.PublicKeys = tempPublicKeys

	tepmAssetTags := make([]string, 0)
	for _, a := range assetTags {
		tepmAssetTags = append(tepmAssetTags, base58.Base58Check{}.Encode(a, common.ZeroByte))
	}
	result.AssetTags = tepmAssetTags

	return result
}