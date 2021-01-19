package privacy_v2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/privacy/coin"
	errhandler "github.com/thanhn-inc/debugtool/privacy/errorhandler"
	"github.com/thanhn-inc/debugtool/privacy/key"
	"github.com/thanhn-inc/debugtool/privacy/operation"
	"github.com/thanhn-inc/debugtool/privacy/privacy_v2/bulletproofs"
	"github.com/thanhn-inc/debugtool/privacy/proof/agg_interface"
	"github.com/thanhn-inc/debugtool/wallet"
)

type PaymentProofV2 struct {
	Version              uint8
	aggregatedRangeProof *bulletproofs.AggregatedRangeProof
	inputCoins           []coin.PlainCoin
	outputCoins          []*coin.CoinV2
}

func (proof *PaymentProofV2) SetVersion() { proof.Version = 2 }
func (proof *PaymentProofV2) GetVersion() uint8 { return 2 }

func (proof PaymentProofV2) GetInputCoins() []coin.PlainCoin { return proof.inputCoins }
func (proof PaymentProofV2) GetOutputCoins() []coin.Coin {
	res := make([]coin.Coin, len(proof.outputCoins))
	for i := 0; i < len(proof.outputCoins); i += 1 {
		res[i] = proof.outputCoins[i]
	}
	return res
}
func (proof PaymentProofV2) GetAggregatedRangeProof() agg_interface.AggregatedRangeProof {
	return proof.aggregatedRangeProof
}

func (proof *PaymentProofV2) SetInputCoins(v []coin.PlainCoin) error {
	var err error
	proof.inputCoins = make([]coin.PlainCoin, len(v))
	for i := 0; i < len(v); i += 1 {
		b := v[i].Bytes()
		if proof.inputCoins[i], err = coin.NewPlainCoinFromByte(b); err != nil {
			return err
		}
	}
	return nil
}

func (proof *PaymentProofV2) SetOutputCoinsV2(v []*coin.CoinV2) error {
	var err error
	proof.outputCoins = make([]*coin.CoinV2, len(v))
	for i := 0; i < len(v); i += 1 {
		b := v[i].Bytes()
		proof.outputCoins[i] = new(coin.CoinV2)
		if err = proof.outputCoins[i].SetBytes(b); err != nil {
			return err
		}
	}
	return nil
}

// v should be all coinv2 or else it would crash
func (proof *PaymentProofV2) SetOutputCoins(v []coin.Coin) error {
	var err error
	proof.outputCoins = make([]*coin.CoinV2, len(v))
	for i := 0; i < len(v); i += 1 {
		proof.outputCoins[i] = new(coin.CoinV2)
		b := v[i].Bytes()
		if err = proof.outputCoins[i].SetBytes(b); err != nil {
			return err
		}
	}
	return nil
}

func (proof *PaymentProofV2) SetAggregatedRangeProof(aggregatedRangeProof *bulletproofs.AggregatedRangeProof){proof.aggregatedRangeProof = aggregatedRangeProof}

func (proof *PaymentProofV2) Init() {
	aggregatedRangeProof := &bulletproofs.AggregatedRangeProof{}
	aggregatedRangeProof.Init()
	proof.Version = 2
	proof.aggregatedRangeProof = aggregatedRangeProof
	proof.inputCoins = []coin.PlainCoin{}
	proof.outputCoins = []*coin.CoinV2{}
}

func (proof PaymentProofV2) MarshalJSON() ([]byte, error) {
	data := proof.Bytes()
	//temp := base58.Base58Check{}.Encode(data, common.ZeroByte)
	temp := base64.StdEncoding.EncodeToString(data)
	return json.Marshal(temp)
}

func (proof *PaymentProofV2) UnmarshalJSON(data []byte) error {
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

func (proof PaymentProofV2) Bytes() []byte {
	var bytes []byte
	bytes = append(bytes, proof.GetVersion())

	comOutputMultiRangeProof := proof.aggregatedRangeProof.Bytes()
	var rangeProofLength uint32 = uint32(len(comOutputMultiRangeProof))
	bytes = append(bytes, common.Uint32ToBytes(rangeProofLength)...)
	bytes = append(bytes, comOutputMultiRangeProof...)

	// InputCoins
	bytes = append(bytes, byte(len(proof.inputCoins)))
	for i := 0; i < len(proof.inputCoins); i++ {
		inputCoins := proof.inputCoins[i].Bytes()
		lenInputCoins := len(inputCoins)
		lenInputCoinsBytes := []byte{}
		if lenInputCoins < 256 {
			lenInputCoinsBytes = []byte{byte(lenInputCoins)}
		} else {
			lenInputCoinsBytes = common.IntToBytes(lenInputCoins)
		}

		bytes = append(bytes, lenInputCoinsBytes...)
		bytes = append(bytes, inputCoins...)
	}

	// OutputCoins
	bytes = append(bytes, byte(len(proof.outputCoins)))
	for i := 0; i < len(proof.outputCoins); i++ {
		outputCoins := proof.outputCoins[i].Bytes()
		lenOutputCoins := len(outputCoins)
		lenOutputCoinsBytes := []byte{}
		if lenOutputCoins < 256 {
			lenOutputCoinsBytes = []byte{byte(lenOutputCoins)}
		} else {
			lenOutputCoinsBytes = common.IntToBytes(lenOutputCoins)
		}

		bytes = append(bytes, lenOutputCoinsBytes...)
		bytes = append(bytes, outputCoins...)
	}

	return bytes
}

func (proof *PaymentProofV2) SetBytes(proofbytes []byte) *errhandler.PrivacyError {
	if len(proofbytes) == 0 {
		return errhandler.NewPrivacyErr(errhandler.InvalidInputToSetBytesErr, errors.New("Proof bytes is zero"))
	}
	if proofbytes[0] != proof.GetVersion() {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Proof bytes version is incorrect"))
	}
	proof.SetVersion()
	offset := 1

	//ComOutputMultiRangeProofSize *aggregatedRangeProof
	if offset+common.Uint32Size >= len(proofbytes) {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range aggregated range proof"))
	}
	lenComOutputMultiRangeUint32, _ := common.BytesToUint32(proofbytes[offset : offset+common.Uint32Size])
	lenComOutputMultiRangeProof := int(lenComOutputMultiRangeUint32)
	offset += common.Uint32Size

	if offset+lenComOutputMultiRangeProof > len(proofbytes) {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range aggregated range proof"))
	}
	if lenComOutputMultiRangeProof > 0 {
		bulletproof := &bulletproofs.AggregatedRangeProof{}
		bulletproof.Init()
		proof.aggregatedRangeProof = bulletproof
		err := proof.aggregatedRangeProof.SetBytes(proofbytes[offset : offset+lenComOutputMultiRangeProof])
		if err != nil {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, err)
		}
		offset += lenComOutputMultiRangeProof
	}

	//InputCoins  []*coin.PlainCoinV1
	if offset >= len(proofbytes) {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
	}
	lenInputCoinsArray := int(proofbytes[offset])
	offset += 1
	proof.inputCoins = make([]coin.PlainCoin, lenInputCoinsArray)
	var err error
	for i := 0; i < lenInputCoinsArray; i++ {
		// try get 1-byte for len
		if offset >= len(proofbytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
		}
		lenInputCoin := int(proofbytes[offset])
		offset += 1

		if offset+lenInputCoin > len(proofbytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
		}
		proof.inputCoins[i], err = coin.NewPlainCoinFromByte(proofbytes[offset : offset+lenInputCoin])
		if err != nil {
			// 1-byte is wrong
			// try get 2-byte for len
			if offset+1 > len(proofbytes) {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
			}
			lenInputCoin = common.BytesToInt(proofbytes[offset-1 : offset+1])
			offset += 1

			if offset+lenInputCoin > len(proofbytes) {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range input coins"))
			}
			proof.inputCoins[i], err = coin.NewPlainCoinFromByte(proofbytes[offset : offset+lenInputCoin])
			if err != nil {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, err)
			}
		}
		offset += lenInputCoin
	}

	//OutputCoins []*privacy.OutputCoin
	if offset >= len(proofbytes) {
		return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
	}
	lenOutputCoinsArray := int(proofbytes[offset])
	offset += 1
	proof.outputCoins = make([]*coin.CoinV2, lenOutputCoinsArray)
	for i := 0; i < lenOutputCoinsArray; i++ {
		proof.outputCoins[i] = new(coin.CoinV2)
		// try get 1-byte for len
		if offset >= len(proofbytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
		}
		lenOutputCoin := int(proofbytes[offset])
		offset += 1

		if offset+lenOutputCoin > len(proofbytes) {
			return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
		}
		err := proof.outputCoins[i].SetBytes(proofbytes[offset : offset+lenOutputCoin])
		if err != nil {
			// 1-byte is wrong
			// try get 2-byte for len
			if offset+1 > len(proofbytes) {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
			}
			lenOutputCoin = common.BytesToInt(proofbytes[offset-1 : offset+1])
			offset += 1

			if offset+lenOutputCoin > len(proofbytes) {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, errors.New("Out of range output coins"))
			}
			err1 := proof.outputCoins[i].SetBytes(proofbytes[offset : offset+lenOutputCoin])
			if err1 != nil {
				return errhandler.NewPrivacyErr(errhandler.SetBytesProofErr, err1)
			}
		}
		offset += lenOutputCoin
	}

	//fmt.Printf("SETBYTES ------------------ %v\n", proof.Bytes())

	return nil
}

func (proof *PaymentProofV2) IsPrivacy() bool {
	return proof.GetOutputCoins()[0].IsEncrypted()
}

// error means the proof is invalid altogether. After this function returns, we will need to check error first
func (proof *PaymentProofV2) IsConfidentialAsset() (bool, error){
	// asset tag consistency check
	assetTagCount := 0
	inputCoins := proof.GetInputCoins()
	for _,c := range inputCoins{
		coin_specific, ok := c.(*coin.CoinV2)
		if !ok{
			return false, errhandler.NewPrivacyErr(errhandler.UnexpectedErr, errors.New("Casting error : CoinV2"))
		}
		if coin_specific.GetAssetTag()!=nil{
			assetTagCount += 1
		}
	}
	outputCoins := proof.GetOutputCoins()
	for _,c := range outputCoins{
		coin_specific, ok := c.(*coin.CoinV2)
		if !ok{
			return false, errhandler.NewPrivacyErr(errhandler.UnexpectedErr, errors.New("Casting error : CoinV2"))
		}
		if coin_specific.GetAssetTag()!=nil{
			assetTagCount += 1
		}
	}
	
	if assetTagCount==len(inputCoins)+len(outputCoins){
		return true, nil
	}else if assetTagCount==0{
		return false, nil		
	}
	return false, errhandler.NewPrivacyErr(errhandler.UnexpectedErr, errors.New("Error : TX contains both confidential asset & non-CA coins"))
}

func Prove(inputCoins []coin.PlainCoin, outputCoins []*coin.CoinV2, sharedSecrets []*operation.Point, hasConfidentialAsset bool, paymentInfo []*key.PaymentInfo) (*PaymentProofV2, error) {
	var err error

	proof := new(PaymentProofV2)
	proof.SetVersion()
	// aggregateproof := new(bulletproofs.AggregatedRangeProof)
	// aggregateproof.Init()
	// proof.aggregatedRangeProof = aggregateproof
	if err = proof.SetInputCoins(inputCoins); err != nil {
		return nil, err
	}
	if err = proof.SetOutputCoinsV2(outputCoins); err != nil {
		return nil, err
	}

	// Prepare range proofs
	n := len(outputCoins)
	outputValues := make([]uint64, n)
	outputRands := make([]*operation.Scalar, n)
	for i := 0; i < n; i += 1 {
		outputValues[i] = outputCoins[i].GetValue()
		outputRands[i] = outputCoins[i].GetRandomness()
	}

	wit := new(bulletproofs.AggregatedRangeWitness)
	wit.Set(outputValues, outputRands)
	if hasConfidentialAsset{
		blinders := make([]*operation.Scalar, len(sharedSecrets))
		for i, _ := range sharedSecrets{
			if sharedSecrets[i]==nil{
				blinders[i] = new(operation.Scalar).FromUint64(0)
			}else{
				blinders[i], err = coin.ComputeAssetTagBlinder(sharedSecrets[i])
				if err != nil {
					return nil, err
				}
			}
		}
		var err error
		wit, err = bulletproofs.TransformWitnessToCAWitness(wit, blinders)
		if err != nil {
			return nil, err
		}

		theBase, err := bulletproofs.GetFirstAssetTag(outputCoins)
		if err != nil {
			return nil, err
		}
		proof.aggregatedRangeProof, err = wit.ProveUsingBase(theBase)

		outputCommitments 	:= make([]*operation.Point, n)
		for i := 0; i < n; i += 1 {
			com, err := outputCoins[i].ComputeCommitmentCA()
			if err!=nil{
				return nil, err
			}
			outputCommitments[i] = com
		}
		proof.aggregatedRangeProof.SetCommitments(outputCommitments)
		if err != nil {
			return nil, err
		}
	}else{
		proof.aggregatedRangeProof, err = wit.Prove()
		if err != nil {
			return nil, err
		}
	}

	// After Prove, we should hide all information in coin details.
	for i, outputCoin := range proof.outputCoins {
		if !wallet.IsPublicKeyBurningAddress(outputCoin.GetPublicKey().ToBytesS()){
			if err = outputCoin.ConcealOutputCoin(paymentInfo[i].PaymentAddress.GetPublicView()); err != nil {
				return nil, err
			}

			// OutputCoin.GetKeyImage should be nil even though we do not have it
			// Because otherwise the RPC server will return the Bytes of [1 0 0 0 0 ...] (the default byte)
			proof.outputCoins[i].SetKeyImage(nil)
		}

	}

	for _, inputCoin := range proof.GetInputCoins(){
		c, ok := inputCoin.(*coin.CoinV2)
		if !ok {
			return nil, errors.New("Input c of PaymentProofV2 must be CoinV2")
		}
		c.ConcealInputCoin()
	}

	return proof, nil
}
