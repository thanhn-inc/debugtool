package privacy_v2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/privacy/coin"
	errhandler "github.com/thanhn-inc/debugtool/privacy/errorhandler"
	"github.com/thanhn-inc/debugtool/privacy/privacy_v1/zeroknowledge/serialnumbernoprivacy"
	"github.com/thanhn-inc/debugtool/privacy/privacy_v1/zeroknowledge/utils"
	"github.com/thanhn-inc/debugtool/privacy/proof/agg_interface"
)

const (
	ConversionProofVersion = 255
)

// For conversion proof, its version will be counted down from 255 -> 0
// It should contain inputCoins of v1 and outputCoins of v2 because it convert v1 to v2
type ConversionProofVer1ToVer2 struct {
	Version                    uint8
	inputCoins                 []*coin.PlainCoinV1
	outputCoins                []*coin.CoinV2
	serialNumberNoPrivacyProof []*serialnumbernoprivacy.SNNoPrivacyProof
}

func (proof ConversionProofVer1ToVer2) MarshalJSON() ([]byte, error) {
	data := proof.Bytes()
	//temp := base58.Base58Check{}.Encode(data, common.ZeroByte)
	temp := base64.StdEncoding.EncodeToString(data)
	return json.Marshal(temp)
}

func (proof *ConversionProofVer1ToVer2) UnmarshalJSON(data []byte) error {
	dataStr := common.EmptyString
	errJson := json.Unmarshal(data, &dataStr)
	if errJson != nil {
		return errJson
	}
	temp, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return err
	}
	errSetBytes := proof.SetBytes(temp)
	if errSetBytes != nil {
		return errSetBytes
	}
	return nil
}

func (proof ConversionProofVer1ToVer2) Init() {
	proof.Version = ConversionProofVersion
	proof.inputCoins = []*coin.PlainCoinV1{}
	proof.outputCoins = []*coin.CoinV2{}
	proof.serialNumberNoPrivacyProof = []*serialnumbernoprivacy.SNNoPrivacyProof{}
}

func (proof ConversionProofVer1ToVer2) GetVersion() uint8 { return ConversionProofVersion }
func (proof *ConversionProofVer1ToVer2) SetVersion(uint8) { proof.Version = ConversionProofVersion }

func (proof ConversionProofVer1ToVer2) GetInputCoins() []coin.PlainCoin {
	res := make([]coin.PlainCoin, len(proof.inputCoins))
	for i := 0; i < len(proof.inputCoins); i += 1 {
		res[i] = proof.inputCoins[i]
	}
	return res
}
func (proof ConversionProofVer1ToVer2) GetOutputCoins() []coin.Coin {
	res := make([]coin.Coin, len(proof.outputCoins))
	for i := 0; i < len(proof.outputCoins); i += 1 {
		res[i] = proof.outputCoins[i]
	}
	return res
}

// InputCoins should be all ver1, else it would crash
func (proof *ConversionProofVer1ToVer2) SetInputCoins(v []coin.PlainCoin) error {
	proof.inputCoins = make([]*coin.PlainCoinV1, len(v))
	for i := 0; i < len(v); i += 1 {
		coin, ok := v[i].(*coin.PlainCoinV1)
		if !ok {
			return errors.New("Input coins should all be PlainCoinV1")
		}
		proof.inputCoins[i] = coin
	}
	return nil
}

// v should be all coinv2 or else it would crash
func (proof *ConversionProofVer1ToVer2) SetOutputCoins(v []coin.Coin) error {
	proof.outputCoins = make([]*coin.CoinV2, len(v))
	for i := 0; i < len(v); i += 1 {
		coin, ok := v[i].(*coin.CoinV2)
		if !ok {
			return errors.New("Output coins should all be CoinV2")
		}
		proof.outputCoins[i] = coin
	}
	return nil
}

// Conversion does not have range proof, everything is nonPrivacy
func (proof ConversionProofVer1ToVer2) GetAggregatedRangeProof() agg_interface.AggregatedRangeProof {
	return nil
}

func (proof ConversionProofVer1ToVer2) Bytes() []byte {
	proofBytes := []byte{ConversionProofVersion}

	// InputCoins
	proofBytes = append(proofBytes, byte(len(proof.inputCoins)))
	for i := 0; i < len(proof.inputCoins); i++ {
		inputCoins := proof.inputCoins[i].Bytes()
		proofBytes = append(proofBytes, byte(len(inputCoins)))
		proofBytes = append(proofBytes, inputCoins...)
	}

	// OutputCoins
	proofBytes = append(proofBytes, byte(len(proof.outputCoins)))
	for i := 0; i < len(proof.outputCoins); i++ {
		outputCoins := proof.outputCoins[i].Bytes()
		lenOutputCoins := len(outputCoins)
		lenOutputCoinsBytes := []byte{}
		if lenOutputCoins < 256 {
			lenOutputCoinsBytes = []byte{byte(lenOutputCoins)}
		} else {
			lenOutputCoinsBytes = common.IntToBytes(lenOutputCoins)
		}

		proofBytes = append(proofBytes, lenOutputCoinsBytes...)
		proofBytes = append(proofBytes, outputCoins...)
	}

	// SNNoPrivacyProofSize
	proofBytes = append(proofBytes, byte(len(proof.serialNumberNoPrivacyProof)))
	for i := 0; i < len(proof.serialNumberNoPrivacyProof); i++ {
		snNoPrivacyProof := proof.serialNumberNoPrivacyProof[i].Bytes()
		proofBytes = append(proofBytes, byte(utils.SnNoPrivacyProofSize))
		proofBytes = append(proofBytes, snNoPrivacyProof...)
	}

	return proofBytes
}

func (proof *ConversionProofVer1ToVer2) SetBytes(proofBytes []byte) *errhandler.PrivacyError {
	if len(proofBytes) == 0 {
		return errhandler.NewPrivacyErr(errhandler.InvalidInputToSetBytesErr, errors.New("Proof bytes = 0"))
	}
	if proofBytes[0] != proof.GetVersion() {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Proof bytes version is not correct"))
	}
	if proof == nil {
		proof = new(ConversionProofVer1ToVer2)
	}
	proof.SetVersion(ConversionProofVersion)
	offset := 1

	//InputCoins  []*coin.PlainCoinV1
	if offset >= len(proofBytes) {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
	}
	lenInputCoinsArray := int(proofBytes[offset])
	offset += 1
	proof.inputCoins = make([]*coin.PlainCoinV1, lenInputCoinsArray)
	for i := 0; i < lenInputCoinsArray; i++ {
		if offset >= len(proofBytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
		}
		lenInputCoin := int(proofBytes[offset])
		offset += 1

		if offset+lenInputCoin > len(proofBytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
		}
		coinBytes := proofBytes[offset : offset+lenInputCoin]
		if pc, err := coin.NewPlainCoinFromByte(coinBytes); err != nil {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, err)
		} else {
			var ok bool
			if proof.inputCoins[i], ok = pc.(*coin.PlainCoinV1); !ok {
				err := errors.New("Cannot assert type of PlainCoin to PlainCoinV1")
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, err)
			}
		}
		offset += lenInputCoin
	}

	//OutputCoins  []*coin.CoinV2
	if offset >= len(proofBytes) {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
	}
	lenOutputCoinsArray := int(proofBytes[offset])
	offset += 1
	proof.outputCoins = make([]*coin.CoinV2, lenOutputCoinsArray)
	for i := 0; i < lenOutputCoinsArray; i++ {
		proof.outputCoins[i] = new(coin.CoinV2)
		// try get 1-byte for len
		if offset >= len(proofBytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
		}
		lenOutputCoin := int(proofBytes[offset])
		offset += 1

		if offset+lenOutputCoin > len(proofBytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
		}
		err := proof.outputCoins[i].SetBytes(proofBytes[offset : offset+lenOutputCoin])
		if err != nil {
			// 1-byte is wrong
			// try get 2-byte for len
			if offset+1 > len(proofBytes) {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
			}
			lenOutputCoin = common.BytesToInt(proofBytes[offset-1 : offset+1])
			offset += 1

			if offset+lenOutputCoin > len(proofBytes) {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
			}
			err1 := proof.outputCoins[i].SetBytes(proofBytes[offset : offset+lenOutputCoin])
			if err1 != nil {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, err1)
			}
		}
		offset += lenOutputCoin

	}

	// SNNoPrivacyProof
	// Set SNNoPrivacyProofSize
	if offset >= len(proofBytes) {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range serial number no privacy proof"))
	}
	lenSNNoPrivacyProofArray := int(proofBytes[offset])
	offset += 1
	proof.serialNumberNoPrivacyProof = make([]*serialnumbernoprivacy.SNNoPrivacyProof, lenSNNoPrivacyProofArray)
	for i := 0; i < lenSNNoPrivacyProofArray; i++ {
		if offset >= len(proofBytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range serial number no privacy proof"))
		}
		lenSNNoPrivacyProof := int(proofBytes[offset])
		offset += 1

		proof.serialNumberNoPrivacyProof[i] = new(serialnumbernoprivacy.SNNoPrivacyProof).Init()
		if offset+lenSNNoPrivacyProof > len(proofBytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range serial number no privacy proof"))
		}
		err := proof.serialNumberNoPrivacyProof[i].SetBytes(proofBytes[offset : offset+lenSNNoPrivacyProof])
		if err != nil {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, err)
		}
		offset += lenSNNoPrivacyProof
	}
	return nil
}

func (proof *ConversionProofVer1ToVer2) IsPrivacy() bool {
	return false
}

func ProveConversion(inputCoins []coin.PlainCoin, outputCoins []*coin.CoinV2, serialnumberWitness []*serialnumbernoprivacy.SNNoPrivacyWitness) (*ConversionProofVer1ToVer2, error) {
	var err error
	proof := new(ConversionProofVer1ToVer2)
	proof.SetVersion(ConversionProofVersion)
	if err = proof.SetInputCoins(inputCoins); err != nil {
		return nil, err
	}
	outputCoinsV2 := make([]coin.Coin, len(outputCoins))
	for i := 0; i < len(outputCoins); i += 1 {
		outputCoinsV2[i] = outputCoins[i]
	}
	if err = proof.SetOutputCoins(outputCoinsV2); err != nil {
		return nil, err
	}

	// Proving that serial number is derived from the committed derivator
	for i := 0; i < len(inputCoins); i++ {
		snNoPrivacyProof, err := serialnumberWitness[i].Prove(nil)
		if err != nil {
			return nil, errhandler.NewPrivacyErr(errhandler.ProveSerialNumberNoPrivacyErr, err)
		}
		proof.serialNumberNoPrivacyProof = append(proof.serialNumberNoPrivacyProof, snNoPrivacyProof)
	}
	// Hide the keyimage :D
	for i := 0; i < len(proof.outputCoins); i++ {
		proof.outputCoins[i].SetKeyImage(nil)
	}
	return proof, nil
}
