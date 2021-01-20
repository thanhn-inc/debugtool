package metadata

import (
	"github.com/thanhn-inc/debugtool/common"
	"strconv"
)

type MetadataBase struct {
	Type int
	Sig []byte
}

func (mb *MetadataBase) SetSig(sig []byte) { mb.Sig = sig }

func (mb MetadataBase) GetSig() []byte { return mb.Sig }

func (mb *MetadataBase) ShouldSignMetaData() bool { return false }

func NewMetadataBase(thisType int) *MetadataBase {
	return &MetadataBase{Type: thisType, Sig: []byte{}}
}

func (mb *MetadataBase) CalculateSize() uint64 {
	return 0
}

func (mb MetadataBase) GetType() int {
	return mb.Type
}

func (mb MetadataBase) Hash() *common.Hash {
	record := strconv.Itoa(mb.Type)
	data := []byte(record)
	hash := common.HashH(data)
	return &hash
}

func (mb MetadataBase) HashWithoutSig() *common.Hash {
	return mb.Hash()
}