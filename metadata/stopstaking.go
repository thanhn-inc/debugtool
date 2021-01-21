package metadata

import (
	"errors"
	"github.com/thanhn-inc/debugtool/common"
	"strconv"
)

type StopAutoStakingMetadata struct {
	MetadataBase
	CommitteePublicKey string
}

func (meta *StopAutoStakingMetadata) Hash() *common.Hash {
	record := strconv.Itoa(meta.Type)
	data := []byte(record)
	data = append(data, meta.Sig...)
	hash := common.HashH(data)
	return &hash
}

func (meta *StopAutoStakingMetadata) HashWithoutSig() *common.Hash {
	return meta.MetadataBase.Hash()
}

func (*StopAutoStakingMetadata) ShouldSignMetaData() bool { return true }

func NewStopAutoStakingMetadata(stopStakingType int, committeePublicKey string) (*StopAutoStakingMetadata, error) {
	if stopStakingType != StopAutoStakingMeta {
		return nil, errors.New("invalid stop staking type")
	}
	metadataBase := NewMetadataBase(stopStakingType)
	return &StopAutoStakingMetadata{
		MetadataBase:       *metadataBase,
		CommitteePublicKey: committeePublicKey,
	}, nil
}

func (stopAutoStakingMetadata StopAutoStakingMetadata) GetType() int {
	return stopAutoStakingMetadata.Type
}

func (stopAutoStakingMetadata *StopAutoStakingMetadata) CalculateSize() uint64 {
	return calculateSize(stopAutoStakingMetadata)
}
