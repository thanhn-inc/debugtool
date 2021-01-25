package tx_ver2

import (
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/privacy/privacy_v2/mlsag"
	"github.com/thanhn-inc/debugtool/transaction/tx_generic"
	"github.com/thanhn-inc/debugtool/transaction/utils"
	"math/big"

	// "github.com/incognitochain/incognito-chain/wallet"
)

//func createPrivKeyMlsagCA(inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, outputSharedSecrets []*privacy.Point, params *tx_generic.TxPrivacyInitParams, commitmentsToZero []*privacy.Point) ([]*privacy.Scalar, error) {
//	senderSK := params.SenderSK
//	// db := params.StateDB
//	tokenID := params.TokenID
//	if tokenID==nil{
//		tokenID = &common.PRVCoinID
//	}
//	rehashed := privacy.HashToPoint(tokenID[:])
//	sumRand := new(privacy.Scalar).FromUint64(0)
//
//	privKeyMlsag := make([]*privacy.Scalar, len(inputCoins)+2)
//	sumInputAssetTagBlinders := new(privacy.Scalar).FromUint64(0)
//	numOfInputs := new(privacy.Scalar).FromUint64(uint64(len(inputCoins)))
//	numOfOutputs := new(privacy.Scalar).FromUint64(uint64(len(outputCoins)))
//	mySkBytes := (*senderSK)[:]
//	for i := 0; i < len(inputCoins); i += 1 {
//		var err error
//		privKeyMlsag[i], err = inputCoins[i].ParsePrivateKeyOfCoin(*senderSK)
//		if err != nil {
//			fmt.Printf("Cannot parse private key of coin %v", err)
//			return nil, err
//		}
//
//		inputCoin_specific, ok := inputCoins[i].(*privacy.CoinV2)
//		if !ok || inputCoin_specific.GetAssetTag()==nil{
//			return nil, errors.New("Cannot cast a coin as v2-CA")
//		}
//
//		isUnblinded := privacy.IsPointEqual(rehashed, inputCoin_specific.GetAssetTag())
//		if isUnblinded{
//			fmt.Printf("Signing TX : processing an unblinded input coin")
//		}
//
//		sharedSecret := new(privacy.Point).Identity()
//		bl := new(privacy.Scalar).FromUint64(0)
//		if !isUnblinded{
//			sharedSecret, err = inputCoin_specific.RecomputeSharedSecret(mySkBytes)
//			if err != nil {
//				fmt.Printf("Cannot recompute shared secret : %v", err)
//				return nil, err
//			}
//
//			bl, err = privacy.ComputeAssetTagBlinder(sharedSecret)
//			if err != nil {
//				return nil, err
//			}
//		}
//
//		fmt.Printf("CA-MLSAG : processing input asset tag %s\n", string(inputCoin_specific.GetAssetTag().MarshalText()))
//		fmt.Printf("Shared secret is %s\n", string(sharedSecret.MarshalText()))
//		fmt.Printf("Blinder is %s\n", string(bl.MarshalText()))
//		v := inputCoin_specific.GetAmount()
//		fmt.Printf("Value is %d\n",v.ToUint64Little())
//		effectiveRCom := new(privacy.Scalar).Mul(bl,v)
//		effectiveRCom.Add(effectiveRCom, inputCoin_specific.GetRandomness())
//
//		sumInputAssetTagBlinders.Add(sumInputAssetTagBlinders, bl)
//		sumRand.Add(sumRand, effectiveRCom)
//	}
//	sumInputAssetTagBlinders.Mul(sumInputAssetTagBlinders, numOfOutputs)
//
//	sumOutputAssetTagBlinders := new(privacy.Scalar).FromUint64(0)
//
//	var err error
//	for i, oc := range outputCoins{
//		if oc.GetAssetTag()==nil{
//			return nil, errors.New("Cannot cast a coin as v2-CA")
//		}
//		// lengths between 0 and len(outputCoins) were rejected before
//		bl := new(privacy.Scalar).FromUint64(0)
//		isUnblinded := privacy.IsPointEqual(rehashed, oc.GetAssetTag())
//		if isUnblinded{
//			fmt.Printf("Signing TX : processing an unblinded output coin")
//		}else{
//			fmt.Printf("Shared secret is %s\n", string(outputSharedSecrets[i].MarshalText()))
//			bl, err = privacy.ComputeAssetTagBlinder(outputSharedSecrets[i])
//			if err != nil {
//				return nil, err
//			}
//		}
//		fmt.Printf("CA-MLSAG : processing output asset tag %s\n", string(oc.GetAssetTag().MarshalText()))
//		fmt.Printf("Blinder is %s\n", string(bl.MarshalText()))
//
//		v := oc.GetAmount()
//		fmt.Printf("Value is %d\n",v.ToUint64Little())
//		effectiveRCom := new(privacy.Scalar).Mul(bl,v)
//		effectiveRCom.Add(effectiveRCom, oc.GetRandomness())
//		sumOutputAssetTagBlinders.Add(sumOutputAssetTagBlinders, bl)
//		sumRand.Sub(sumRand, effectiveRCom)
//	}
//	sumOutputAssetTagBlinders.Mul(sumOutputAssetTagBlinders, numOfInputs)
//
//	// 2 final elements in `private keys` for MLSAG
//	assetSum := new(privacy.Scalar).Sub(sumInputAssetTagBlinders, sumOutputAssetTagBlinders)
//	firstCommitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], assetSum)
//	secondCommitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], sumRand)
//	if len(commitmentsToZero)!=2{
//		fmt.Printf("Received %d points to check when signing MLSAG", len(commitmentsToZero))
//		return nil, utils.NewTransactionErr(utils.UnexpectedError, errors.New("Error : need exactly 2 points for MLSAG double-checking"))
//	}
//	match1 := privacy.IsPointEqual(firstCommitmentToZeroRecomputed, commitmentsToZero[0])
//	match2 := privacy.IsPointEqual(secondCommitmentToZeroRecomputed, commitmentsToZero[1])
//	if !match1 || !match2{
//		return nil, utils.NewTransactionErr(utils.UnexpectedError, errors.New("Error : asset tag sum or commitment sum mismatch"))
//	}
//
//	fmt.Printf("Last 2 private keys will correspond to points %s and %s", firstCommitmentToZeroRecomputed.MarshalText(), secondCommitmentToZeroRecomputed.MarshalText())
//
//	privKeyMlsag[len(inputCoins)] 	= assetSum
//	privKeyMlsag[len(inputCoins)+1]	= sumRand
//	return privKeyMlsag, nil
//}
//
//func generateMlsagRingWithIndexesCA(inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, params *tx_generic.TxPrivacyInitParams, pi int, shardID byte, ringSize int) (*mlsag.Ring, [][]*big.Int, []*privacy.Point, error) {
//
//	lenOTA, err := statedb.GetOTACoinLength(params.StateDB, common.ConfidentialAssetID, shardID)
//	if err != nil || lenOTA == nil {
//		fmt.Printf("Getting length of commitment error, either database length ota is empty or has error, error = %v", err)
//		return nil, nil, nil, err
//	}
//	outputCoinsAsGeneric := make([]privacy.Coin, len(outputCoins))
//	for i:=0;i<len(outputCoins);i++{
//		outputCoinsAsGeneric[i] = outputCoins[i]
//	}
//	sumOutputsWithFee := tx_generic.CalculateSumOutputsWithFee(outputCoinsAsGeneric, params.Fee)
//	inCount := new(privacy.Scalar).FromUint64(uint64(len(inputCoins)))
//	outCount := new(privacy.Scalar).FromUint64(uint64(len(outputCoins)))
//
//	sumOutputAssetTags := new(privacy.Point).Identity()
//	for _, oc := range outputCoins{
//		if oc.GetAssetTag()==nil{
//			fmt.Printf("CA error: missing asset tag for signing in output coin - %v", oc.Bytes())
//			err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : an output coin does not have asset tag"))
//			return nil, nil, nil, err
//		}
//		sumOutputAssetTags.Add(sumOutputAssetTags, oc.GetAssetTag())
//	}
//	sumOutputAssetTags.ScalarMult(sumOutputAssetTags, inCount)
//
//	indexes := make([][]*big.Int, ringSize)
//	ring := make([][]*privacy.Point, ringSize)
//	var lastTwoColumnsCommitmentToZero []*privacy.Point
//	for i := 0; i < ringSize; i += 1 {
//		sumInputs := new(privacy.Point).Identity()
//		sumInputs.Sub(sumInputs, sumOutputsWithFee)
//		sumInputAssetTags := new(privacy.Point).Identity()
//
//		row := make([]*privacy.Point, len(inputCoins))
//		rowIndexes := make([]*big.Int, len(inputCoins))
//		if i == pi {
//			for j := 0; j < len(inputCoins); j += 1 {
//				row[j] = inputCoins[j].GetPublicKey()
//				publicKeyBytes := inputCoins[j].GetPublicKey().ToBytesS()
//				if rowIndexes[j], err = statedb.GetOTACoinIndex(params.StateDB, common.ConfidentialAssetID, publicKeyBytes); err != nil {
//					fmt.Printf("Getting commitment index error %v ", err)
//					return nil, nil, nil, err
//				}
//				sumInputs.Add(sumInputs, inputCoins[j].GetCommitment())
//				inputCoin_specific, ok := inputCoins[j].(*privacy.CoinV2)
//				if !ok{
//					return nil, nil, nil, errors.New("Cannot cast a coin as v2")
//				}
//				if inputCoin_specific.GetAssetTag()==nil{
//					fmt.Printf("CA error: missing asset tag for signing in input coin - %v", inputCoin_specific.Bytes())
//					err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : an input coin does not have asset tag"))
//					return nil, nil, nil, err
//				}
//				sumInputAssetTags.Add(sumInputAssetTags, inputCoin_specific.GetAssetTag())
//			}
//		} else {
//			for j := 0; j < len(inputCoins); j += 1 {
//				rowIndexes[j], _ = common.RandBigIntMaxRange(lenOTA)
//				coinBytes, err := statedb.GetOTACoinByIndex(params.StateDB, common.ConfidentialAssetID, rowIndexes[j].Uint64(), shardID)
//				if err != nil {
//					fmt.Printf("Get coinv2 by index error %v ", err)
//					return nil, nil, nil, err
//				}
//				coinDB := new(privacy.CoinV2)
//				if err := coinDB.SetBytes(coinBytes); err != nil {
//					fmt.Printf("Cannot parse coinv2 byte error %v ", err)
//					return nil, nil, nil, err
//				}
//				row[j] = coinDB.GetPublicKey()
//				sumInputs.Add(sumInputs, coinDB.GetCommitment())
//				if coinDB.GetAssetTag()==nil{
//					fmt.Printf("CA error: missing asset tag for signing in DB coin - %v", coinBytes)
//					err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : a CA coin in DB does not have asset tag"))
//					return nil, nil, nil, err
//				}
//				sumInputAssetTags.Add(sumInputAssetTags, coinDB.GetAssetTag())
//			}
//		}
//		sumInputAssetTags.ScalarMult(sumInputAssetTags, outCount)
//
//		assetSum := new(privacy.Point).Sub(sumInputAssetTags, sumOutputAssetTags)
//		row = append(row, assetSum)
//		row = append(row, sumInputs)
//		if i==pi{
//			fmt.Printf("Last 2 columns in ring are %s and %s\n", assetSum.MarshalText(), sumInputs.MarshalText())
//			lastTwoColumnsCommitmentToZero = []*privacy.Point{assetSum, sumInputs}
//		}
//
//		ring[i] = row
//		indexes[i] = rowIndexes
//	}
//	return mlsag.NewRing(ring), indexes, lastTwoColumnsCommitmentToZero, nil
//}
//
//func (tx *Tx) proveCA(params *tx_generic.TxPrivacyInitParams) (bool, error) {
//	var err error
//	var outputCoins 	[]*privacy.CoinV2
//	var sharedSecrets 	[]*privacy.Point
//	// fmt.Printf("tokenID is %v\n",params.TokenID)
//	var numOfCoinsBurned uint = 0
//	var isBurning bool = false
//	for _,inf := range params.PaymentInfo{
//		c, ss, err := createUniqueOTACoinCA(inf, params.TokenID, params.StateDB)
//		if err != nil {
//			fmt.Printf("Cannot parse outputCoinV2 to outputCoins, error %v ", err)
//			return false, err
//		}
//		// the only way err!=nil but ss==nil is a coin meant for burning address
//		if ss==nil{
//			isBurning = true
//			numOfCoinsBurned += 1
//		}
//		sharedSecrets 	= append(sharedSecrets, ss)
//		outputCoins 	= append(outputCoins, c)
//	}
//	// first, reject the invalid case. After this, isBurning will correctly determine if TX is burning
//	if numOfCoinsBurned>1{
//		fmt.Printf("Cannot burn multiple coins")
//		return false, utils.NewTransactionErr(utils.UnexpectedError, errors.New("output must not have more than 1 burned coin"))
//	}
//	// outputCoins, err := newCoinV2ArrayFromPaymentInfoArray(params.PaymentInfo, params.TokenID, params.StateDB)
//
//	// inputCoins is plainCoin because it may have coinV1 with coinV2
//	inputCoins := params.InputCoins
//	tx.Proof, err = privacy.ProveV2(inputCoins, outputCoins, sharedSecrets, true, params.PaymentInfo)
//	if err != nil {
//		fmt.Printf("Error in privacy_v2.Prove, error %v ", err)
//		return false, err
//	}
//
//	if tx.ShouldSignMetaData() {
//		if err := tx.signMetadata(params.SenderSK); err != nil {
//			fmt.Printf("Cannot signOnMessage txMetadata in shouldSignMetadata")
//			return false, err
//		}
//	}
//	err = tx.signCA(inputCoins, outputCoins, sharedSecrets, params, tx.Hash()[:])
//	return isBurning, err
//}
//
//func (tx *Tx) signCA(inp []privacy.PlainCoin, out []*privacy.CoinV2, outputSharedSecrets []*privacy.Point, params *tx_generic.TxPrivacyInitParams, hashedMessage []byte) error {
//	if tx.Sig != nil {
//		return utils.NewTransactionErr(utils.UnexpectedError, errors.New("input transaction must be an unsigned one"))
//	}
//	ringSize := privacy.RingSize
//
//	// Generate Ring
//	piBig,piErr := common.RandBigIntMaxRange(big.NewInt(int64(ringSize)))
//	if piErr!=nil{
//		return piErr
//	}
//	var pi int = int(piBig.Int64())
//	shardID := common.GetShardIDFromLastByte(tx.PubKeyLastByteSender)
//	ring, indexes, commitmentsToZero, err := generateMlsagRingWithIndexesCA(inp, out, params, pi, shardID, ringSize)
//	if err != nil {
//		fmt.Printf("generateMLSAGRingWithIndexes got error %v ", err)
//		return err
//	}
//
//	// Set SigPubKey
//	txSigPubKey := new(SigPubKey)
//	txSigPubKey.Indexes = indexes
//	tx.SigPubKey, err = txSigPubKey.Bytes()
//	if err != nil {
//		fmt.Printf("tx.SigPubKey cannot parse from Bytes, error %v ", err)
//		return err
//	}
//
//	// Set sigPrivKey
//	privKeysMlsag, err := createPrivKeyMlsagCA(inp, out, outputSharedSecrets, params, shardID, commitmentsToZero)
//	if err != nil {
//		fmt.Printf("Cannot create private key of mlsag: %v", err)
//		return err
//	}
//	sag := mlsag.NewMlsag(privKeysMlsag, ring, pi)
//	sk, err := privacy.ArrayScalarToBytes(&privKeysMlsag)
//	if err != nil {
//		fmt.Printf("tx.SigPrivKey cannot parse arrayScalar to Bytes, error %v ", err)
//		return err
//	}
//	tx.SetPrivateKey(sk)
//
//	// Set Signature
//	mlsagSignature, err := sag.SignConfidentialAsset(hashedMessage)
//	if err != nil {
//		fmt.Printf("Cannot signOnMessage mlsagSignature, error %v ", err)
//		return err
//	}
//	// inputCoins already hold keyImage so set to nil to reduce size
//	mlsagSignature.SetKeyImages(nil)
//	tx.Sig, err = mlsagSignature.ToBytes()
//
//	return err
//}
//
//func reconstructRingCA(sigPubKey []byte, sumOutputsWithFee , sumOutputAssetTags *privacy.Point, numOfOutputs *privacy.Scalar, transactionStateDB *statedb.StateDB, shardID byte, tokenID *common.Hash) (*mlsag.Ring, error) {
//	txSigPubKey := new(SigPubKey)
//	if err := txSigPubKey.SetBytes(sigPubKey); err != nil {
//		errStr := fmt.Sprintf("Error when parsing bytes of txSigPubKey %v", err)
//		return nil, utils.NewTransactionErr(utils.UnexpectedError, errors.New(errStr))
//	}
//	indexes := txSigPubKey.Indexes
//	n := len(indexes)
//	if n == 0 {
//		return nil, errors.New("Cannot get ring from Indexes: Indexes is empty")
//	}
//
//	m := len(indexes[0])
//
//	ring := make([][]*privacy.Point, n)
//	for i := 0; i < n; i += 1 {
//		sumCommitment := new(privacy.Point).Identity()
//		sumCommitment.Sub(sumCommitment, sumOutputsWithFee)
//		sumAssetTags := new(privacy.Point).Identity()
//		sumAssetTags.Sub(sumAssetTags, sumOutputAssetTags)
//		row := make([]*privacy.Point, m+2)
//		for j := 0; j < m; j += 1 {
//			index := indexes[i][j]
//			randomCoinBytes, err := statedb.GetOTACoinByIndex(transactionStateDB, *tokenID, index.Uint64(), shardID)
//			if err != nil {
//				fmt.Printf("Get random onetimeaddresscoin error %v ", err)
//				return nil, err
//			}
//			randomCoin := new(privacy.CoinV2)
//			if err := randomCoin.SetBytes(randomCoinBytes); err != nil {
//				fmt.Printf("Set coin Byte error %v ", err)
//				return nil, err
//			}
//			row[j] = randomCoin.GetPublicKey()
//			sumCommitment.Add(sumCommitment, randomCoin.GetCommitment())
//			temp := new(privacy.Point).ScalarMult(randomCoin.GetAssetTag(), numOfOutputs)
//			sumAssetTags.Add(sumAssetTags, temp)
//		}
//
//		row[m] 	 = new(privacy.Point).Set(sumAssetTags)
//		row[m+1] = new(privacy.Point).Set(sumCommitment)
//		ring[i] = row
//	}
//	return mlsag.NewRing(ring), nil
//}

//Create unique OTA coin without the help of the db
func createUniqueOTACoinCA(paymentInfo *privacy.PaymentInfo, tokenID *common.Hash) (*privacy.CoinV2, *privacy.Point, error) {
	if tokenID == nil {
		tokenID = &common.PRVCoinID
	}
	c, sharedSecret, err := privacy.NewCoinCA(paymentInfo, tokenID)
	if tokenID != nil && sharedSecret != nil && c != nil && c.GetAssetTag() != nil {
		fmt.Printf("Created a new coin with tokenID %s, shared secret %s, asset tag %s\n", tokenID.String(), sharedSecret.MarshalText(), c.GetAssetTag().MarshalText())
	}
	if err != nil {
		fmt.Printf("Cannot parse coin based on payment info err: %v", err)
		return nil, nil, err
	}
	// If previously created coin is burning address
	if sharedSecret == nil {
		// assetTag := privacy.HashToPoint(tokenID[:])
		// c.SetAssetTag(assetTag)
		return c, nil, nil // No need to check db
	}
	return c, sharedSecret, nil
}

func createPrivKeyMlsagCA(inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, outputSharedSecrets []*privacy.Point, params *tx_generic.TxPrivacyInitParams, shardID byte, commitmentsToZero []*privacy.Point) ([]*privacy.Scalar, error) {
	senderSK := params.SenderSK
	// db := params.StateDB
	tokenID := params.TokenID
	if tokenID == nil {
		tokenID = &common.PRVCoinID
	}
	rehashed := privacy.HashToPoint(tokenID[:])
	sumRand := new(privacy.Scalar).FromUint64(0)

	privKeyMlsag := make([]*privacy.Scalar, len(inputCoins)+2)
	sumInputAssetTagBlinders := new(privacy.Scalar).FromUint64(0)
	numOfInputs := new(privacy.Scalar).FromUint64(uint64(len(inputCoins)))
	numOfOutputs := new(privacy.Scalar).FromUint64(uint64(len(outputCoins)))
	mySkBytes := (*senderSK)[:]
	for i := 0; i < len(inputCoins); i += 1 {
		var err error
		privKeyMlsag[i], err = inputCoins[i].ParsePrivateKeyOfCoin(*senderSK)
		if err != nil {
			fmt.Printf("Cannot parse private key of coin %v", err)
			return nil, err
		}

		inputCoin_specific, ok := inputCoins[i].(*privacy.CoinV2)
		if !ok || inputCoin_specific.GetAssetTag() == nil {
			return nil, errors.New("Cannot cast a coin as v2-CA")
		}

		isUnblinded := privacy.IsPointEqual(rehashed, inputCoin_specific.GetAssetTag())
		if isUnblinded {
			fmt.Printf("Signing TX : processing an unblinded input coin")
		}

		sharedSecret := new(privacy.Point).Identity()
		bl := new(privacy.Scalar).FromUint64(0)
		if !isUnblinded {
			sharedSecret, err = inputCoin_specific.RecomputeSharedSecret(mySkBytes)
			if err != nil {
				fmt.Printf("Cannot recompute shared secret : %v", err)
				return nil, err
			}

			bl, err = privacy.ComputeAssetTagBlinder(sharedSecret)
			if err != nil {
				return nil, err
			}
		}

		fmt.Printf("CA-MLSAG : processing input asset tag %s\n", string(inputCoin_specific.GetAssetTag().MarshalText()))
		fmt.Printf("Shared secret is %s\n", string(sharedSecret.MarshalText()))
		fmt.Printf("Blinder is %s\n", string(bl.MarshalText()))
		v := inputCoin_specific.GetAmount()
		fmt.Printf("Value is %d\n", v.ToUint64Little())
		effectiveRCom := new(privacy.Scalar).Mul(bl, v)
		effectiveRCom.Add(effectiveRCom, inputCoin_specific.GetRandomness())

		sumInputAssetTagBlinders.Add(sumInputAssetTagBlinders, bl)
		sumRand.Add(sumRand, effectiveRCom)
	}
	sumInputAssetTagBlinders.Mul(sumInputAssetTagBlinders, numOfOutputs)

	sumOutputAssetTagBlinders := new(privacy.Scalar).FromUint64(0)

	var err error
	for i, oc := range outputCoins {
		if oc.GetAssetTag() == nil {
			return nil, errors.New("Cannot cast a coin as v2-CA")
		}
		// lengths between 0 and len(outputCoins) were rejected before
		bl := new(privacy.Scalar).FromUint64(0)
		isUnblinded := privacy.IsPointEqual(rehashed, oc.GetAssetTag())
		if isUnblinded {
			fmt.Printf("Signing TX : processing an unblinded output coin")
		} else {
			fmt.Printf("Shared secret is %s\n", string(outputSharedSecrets[i].MarshalText()))
			bl, err = privacy.ComputeAssetTagBlinder(outputSharedSecrets[i])
			if err != nil {
				return nil, err
			}
		}
		fmt.Printf("CA-MLSAG : processing output asset tag %s\n", string(oc.GetAssetTag().MarshalText()))
		fmt.Printf("Blinder is %s\n", string(bl.MarshalText()))

		v := oc.GetAmount()
		fmt.Printf("Value is %d\n", v.ToUint64Little())
		effectiveRCom := new(privacy.Scalar).Mul(bl, v)
		effectiveRCom.Add(effectiveRCom, oc.GetRandomness())
		sumOutputAssetTagBlinders.Add(sumOutputAssetTagBlinders, bl)
		sumRand.Sub(sumRand, effectiveRCom)
	}
	sumOutputAssetTagBlinders.Mul(sumOutputAssetTagBlinders, numOfInputs)

	// 2 final elements in `private keys` for MLSAG
	assetSum := new(privacy.Scalar).Sub(sumInputAssetTagBlinders, sumOutputAssetTagBlinders)
	firstCommitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], assetSum)
	secondCommitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], sumRand)
	if len(commitmentsToZero) != 2 {
		fmt.Printf("Received %d points to check when signing MLSAG", len(commitmentsToZero))
		return nil, utils.NewTransactionErr(utils.UnexpectedError, errors.New("Error : need exactly 2 points for MLSAG double-checking"))
	}
	match1 := privacy.IsPointEqual(firstCommitmentToZeroRecomputed, commitmentsToZero[0])
	match2 := privacy.IsPointEqual(secondCommitmentToZeroRecomputed, commitmentsToZero[1])
	if !match1 || !match2 {
		return nil, utils.NewTransactionErr(utils.UnexpectedError, errors.New("Error : asset tag sum or commitment sum mismatch"))
	}

	fmt.Printf("Last 2 private keys will correspond to points %s and %s", firstCommitmentToZeroRecomputed.MarshalText(), secondCommitmentToZeroRecomputed.MarshalText())

	privKeyMlsag[len(inputCoins)] = assetSum
	privKeyMlsag[len(inputCoins)+1] = sumRand
	return privKeyMlsag, nil
}

func generateMlsagRingWithIndexesCA(inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, params *tx_generic.TxPrivacyInitParams, pi int, shardID byte, ringSize int) (*mlsag.Ring, [][]*big.Int, []*privacy.Point, error) {
	cmtIndices, myIndices, commitments, publicKeys, assetTags, err := ParseParamsForRing(params.Kvargs, len(inputCoins), ringSize)
	if err != nil {
		return nil, nil, nil, utils.NewTransactionErr(utils.UnexpectedError, errors.New(fmt.Sprintf("ParseParamsForRing error: %v", err)))
	}
	if len(assetTags) < len(inputCoins)*(ringSize-1) {
		return nil, nil, nil, errors.New(fmt.Sprintf("not enough decoy asset tags: have %v, need at least %v (%v input coins).", len(assetTags), len(inputCoins)*(ringSize-1), len(inputCoins)))
	}

	outputCoinsAsGeneric := make([]privacy.Coin, len(outputCoins))
	for i := 0; i < len(outputCoins); i++ {
		outputCoinsAsGeneric[i] = outputCoins[i]
	}
	sumOutputsWithFee := tx_generic.CalculateSumOutputsWithFee(outputCoinsAsGeneric, params.Fee)
	inCount := new(privacy.Scalar).FromUint64(uint64(len(inputCoins)))
	outCount := new(privacy.Scalar).FromUint64(uint64(len(outputCoins)))

	sumOutputAssetTags := new(privacy.Point).Identity()
	for _, oc := range outputCoins {
		if oc.GetAssetTag() == nil {
			fmt.Printf("CA error: missing asset tag for signing in output coin - %v", oc.Bytes())
			err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : an output coin does not have asset tag"))
			return nil, nil, nil, err
		}
		sumOutputAssetTags.Add(sumOutputAssetTags, oc.GetAssetTag())
	}
	sumOutputAssetTags.ScalarMult(sumOutputAssetTags, inCount)

	indexes := make([][]*big.Int, ringSize)
	ring := make([][]*privacy.Point, ringSize)
	var lastTwoColumnsCommitmentToZero []*privacy.Point
	currentIndex := 0
	for i := 0; i < ringSize; i += 1 {
		sumInputs := new(privacy.Point).Identity()
		sumInputs.Sub(sumInputs, sumOutputsWithFee)
		sumInputAssetTags := new(privacy.Point).Identity()

		row := make([]*privacy.Point, len(inputCoins))
		rowIndexes := make([]*big.Int, len(inputCoins))
		if i == pi {
			for j := 0; j < len(inputCoins); j += 1 {
				row[j] = inputCoins[j].GetPublicKey()
				rowIndexes[j] = new(big.Int).SetUint64(myIndices[j])
				sumInputs.Add(sumInputs, inputCoins[j].GetCommitment())
				inputCoin_specific, ok := inputCoins[j].(*privacy.CoinV2)
				if !ok {
					return nil, nil, nil, errors.New("Cannot cast a coin as v2")
				}
				if inputCoin_specific.GetAssetTag() == nil {
					fmt.Printf("CA error: missing asset tag for signing in input coin - %v", inputCoin_specific.Bytes())
					err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : an input coin does not have asset tag"))
					return nil, nil, nil, err
				}
				sumInputAssetTags.Add(sumInputAssetTags, inputCoin_specific.GetAssetTag())
			}
		} else {
			for j := 0; j < len(inputCoins); j += 1 {
				rowIndexes[j] = new(big.Int).SetUint64(cmtIndices[currentIndex])
				row[j] = publicKeys[currentIndex]
				sumInputs.Add(sumInputs, commitments[currentIndex])
				if assetTags[currentIndex] == nil {
					fmt.Printf("CA error: missing asset tag for signing in DB coin - %v", currentIndex)
					err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : a CA coin in DB does not have asset tag"))
					return nil, nil, nil, err
				}
				sumInputAssetTags.Add(sumInputAssetTags, assetTags[currentIndex])
				currentIndex += 1
			}
		}
		sumInputAssetTags.ScalarMult(sumInputAssetTags, outCount)

		assetSum := new(privacy.Point).Sub(sumInputAssetTags, sumOutputAssetTags)
		row = append(row, assetSum)
		row = append(row, sumInputs)
		if i == pi {
			fmt.Printf("Last 2 columns in ring are %s and %s\n", assetSum.MarshalText(), sumInputs.MarshalText())
			lastTwoColumnsCommitmentToZero = []*privacy.Point{assetSum, sumInputs}
		}

		ring[i] = row
		indexes[i] = rowIndexes
	}
	return mlsag.NewRing(ring), indexes, lastTwoColumnsCommitmentToZero, nil
}

func (tx *Tx) proveCA(params *tx_generic.TxPrivacyInitParams) (bool, error) {
	var err error
	var outputCoins []*privacy.CoinV2
	var sharedSecrets []*privacy.Point
	// fmt.Printf("tokenID is %v\n",params.TokenID)
	var numOfCoinsBurned uint = 0
	var isBurning bool = false
	for _, inf := range params.PaymentInfo {
		c, ss, err := createUniqueOTACoinCA(inf, params.TokenID)
		if err != nil {
			fmt.Printf("Cannot parse outputCoinV2 to outputCoins, error %v ", err)
			return false, err
		}
		// the only way err!=nil but ss==nil is a coin meant for burning address
		if ss == nil {
			isBurning = true
			numOfCoinsBurned += 1
		}
		sharedSecrets = append(sharedSecrets, ss)
		outputCoins = append(outputCoins, c)
	}
	// first, reject the invalid case. After this, isBurning will correctly determine if TX is burning
	if numOfCoinsBurned > 1 {
		fmt.Printf("Cannot burn multiple coins")
		return false, utils.NewTransactionErr(utils.UnexpectedError, errors.New("output must not have more than 1 burned coin"))
	}
	// outputCoins, err := newCoinV2ArrayFromPaymentInfoArray(params.PaymentInfo, params.TokenID, params.StateDB)

	// inputCoins is plainCoin because it may have coinV1 with coinV2
	inputCoins := params.InputCoins
	tx.Proof, err = privacy.ProveV2(inputCoins, outputCoins, sharedSecrets, true, params.PaymentInfo)
	if err != nil {
		fmt.Printf("Error in privacy_v2.Prove, error %v ", err)
		return false, err
	}

	if tx.ShouldSignMetaData() {
		if err := tx.signMetadata(params.SenderSK); err != nil {
			fmt.Printf("Cannot signOnMessage txMetadata in shouldSignMetadata")
			return false, err
		}
	}
	err = tx.signCA(inputCoins, outputCoins, sharedSecrets, params, tx.Hash()[:])
	return isBurning, err
}

func (tx *Tx) signCA(inp []privacy.PlainCoin, out []*privacy.CoinV2, outputSharedSecrets []*privacy.Point, params *tx_generic.TxPrivacyInitParams, hashedMessage []byte) error {
	if tx.Sig != nil {
		return utils.NewTransactionErr(utils.UnexpectedError, errors.New("input transaction must be an unsigned one"))
	}
	ringSize := privacy.RingSize

	// Generate Ring
	piBig, piErr := common.RandBigIntMaxRange(big.NewInt(int64(ringSize)))
	if piErr != nil {
		return piErr
	}
	var pi int = int(piBig.Int64())
	shardID := common.GetShardIDFromLastByte(tx.PubKeyLastByteSender)
	ring, indexes, commitmentsToZero, err := generateMlsagRingWithIndexesCA(inp, out, params, pi, shardID, ringSize)
	if err != nil {
		fmt.Printf("generateMLSAGRingWithIndexes got error %v ", err)
		return err
	}

	// Set SigPubKey
	txSigPubKey := new(SigPubKey)
	txSigPubKey.Indexes = indexes
	tx.SigPubKey, err = txSigPubKey.Bytes()
	if err != nil {
		fmt.Printf("tx.SigPubKey cannot parse from Bytes, error %v ", err)
		return err
	}

	// Set sigPrivKey
	privKeysMlsag, err := createPrivKeyMlsagCA(inp, out, outputSharedSecrets, params, shardID, commitmentsToZero)
	if err != nil {
		fmt.Printf("Cannot create private key of mlsag: %v", err)
		return err
	}
	sag := mlsag.NewMlsag(privKeysMlsag, ring, pi)
	sk, err := privacy.ArrayScalarToBytes(&privKeysMlsag)
	if err != nil {
		fmt.Printf("tx.SigPrivKey cannot parse arrayScalar to Bytes, error %v ", err)
		return err
	}
	tx.SetPrivateKey(sk)

	// Set Signature
	mlsagSignature, err := sag.SignConfidentialAsset(hashedMessage)
	if err != nil {
		fmt.Printf("Cannot signOnMessage mlsagSignature, error %v ", err)
		return err
	}
	// inputCoins already hold keyImage so set to nil to reduce size
	mlsagSignature.SetKeyImages(nil)
	tx.Sig, err = mlsagSignature.ToBytes()

	return err
}
