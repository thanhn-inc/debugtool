package tx_ver2

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/incognitokey"
	"github.com/thanhn-inc/debugtool/metadata"
	"github.com/thanhn-inc/debugtool/privacy"
	"github.com/thanhn-inc/debugtool/privacy/privacy_v1/zeroknowledge/serialnumbernoprivacy"
	"github.com/thanhn-inc/debugtool/privacy/privacy_v2"
	"github.com/thanhn-inc/debugtool/transaction/tx_generic"
	"github.com/thanhn-inc/debugtool/transaction/utils"

	"strconv"
	"time"
)

// ================ TX NORMAL CONVERSION =================

type TxConvertVer1ToVer2InitParams struct {
	senderSK    *privacy.PrivateKey
	paymentInfo []*privacy.PaymentInfo
	inputCoins  []privacy.PlainCoin
	fee         uint64
	tokenID     *common.Hash // default is nil -> use for prv coin
	metaData    metadata.Metadata
	info        []byte // 512 bytes
	kvargs      map[string]interface{}
}

func NewTxConvertVer1ToVer2InitParams(senderSK *privacy.PrivateKey,
	paymentInfo []*privacy.PaymentInfo,
	inputCoins []privacy.PlainCoin,
	fee uint64,
	tokenID *common.Hash, // default is nil -> use for prv coin
	metaData metadata.Metadata,
	info []byte,
	kvargs map[string]interface{}) *TxConvertVer1ToVer2InitParams {
	// make sure info is not nil ; zero value for it is []byte{}

	if info == nil {
		info = []byte{}
	}

	return &TxConvertVer1ToVer2InitParams{
		tokenID:     tokenID,
		inputCoins:  inputCoins,
		fee:         fee,
		metaData:    metaData,
		paymentInfo: paymentInfo,
		senderSK:    senderSK,
		info:        info,
		kvargs:      kvargs,
	}
}

func validateTxConvertVer1ToVer2Params(params *TxConvertVer1ToVer2InitParams) error {
	if len(params.inputCoins) > 255 {
		return utils.NewTransactionErr(utils.InputCoinIsVeryLargeError, nil, strconv.Itoa(len(params.inputCoins)))
	}
	if len(params.paymentInfo) > 254 {
		return utils.NewTransactionErr(utils.PaymentInfoIsVeryLargeError, nil, strconv.Itoa(len(params.paymentInfo)))
	}

	sumInput, sumOutput := uint64(0), uint64(0)
	for _, c := range params.inputCoins {
		if c.GetVersion() != 1 {
			err := errors.New("TxConversion should only have inputCoins version 1")
			return utils.NewTransactionErr(utils.InvalidInputCoinVersionErr, err)
		}

		//Verify if input coins have been concealed
		if c.GetRandomness() == nil || c.GetSNDerivator() == nil || c.GetPublicKey() == nil || c.GetCommitment() == nil {
			err := errors.New("input coins should not be concealed")
			return utils.NewTransactionErr(utils.InvalidInputCoinVersionErr, err)
		}
		sumInput += c.GetValue()
	}
	for _, c := range params.paymentInfo {
		sumOutput += c.Amount
	}
	if sumInput != sumOutput+params.fee {
		err := errors.New("TxConversion's sum input coin and output coin (with fee) is not the same")
		return utils.NewTransactionErr(utils.SumInputCoinsAndOutputCoinsError, err)
	}

	if params.tokenID == nil {
		// using default PRV
		params.tokenID = &common.Hash{}
		if err := params.tokenID.SetBytes(common.PRVCoinID[:]); err != nil {
			return utils.NewTransactionErr(utils.TokenIDInvalidError, err, params.tokenID.String())
		}
	}
	return nil
}

func initializeTxConversion(tx *Tx, params *TxConvertVer1ToVer2InitParams) error {
	var err error
	// Get Keyset from param
	senderKeySet := incognitokey.KeySet{}
	if err := senderKeySet.InitFromPrivateKey(params.senderSK); err != nil {
		return utils.NewTransactionErr(utils.PrivateKeySenderInvalidError, err)
	}

	// Tx: initialize some values
	tx.Fee = params.fee
	tx.Version = utils.TxConversionVersion12Number
	tx.Type = common.TxConversionType
	tx.Metadata = params.metaData
	tx.PubKeyLastByteSender = common.GetShardIDFromLastByte(senderKeySet.PaymentAddress.Pk[len(senderKeySet.PaymentAddress.Pk)-1])

	if tx.LockTime == 0 {
		tx.LockTime = time.Now().Unix()
	}
	if tx.Info, err = tx_generic.GetTxInfo(params.info); err != nil {
		return err
	}
	return nil
}

func InitConversion(tx *Tx, params *TxConvertVer1ToVer2InitParams) error {
	// validate again
	if err := validateTxConvertVer1ToVer2Params(params); err != nil {
		return err
	}
	if err := initializeTxConversion(tx, params); err != nil {
		return err
	}
	if err := proveConversion(tx, params); err != nil {
		return err
	}
	jsb, _ := json.Marshal(tx)
	fmt.Printf("Init conversion complete ! -> %s", string(jsb))
	txSize := tx.GetTxActualSize()
	if txSize > common.MaxTxSize {
		return utils.NewTransactionErr(utils.ExceedSizeTx, nil, strconv.Itoa(int(txSize)))
	}
	return nil
}

func createOutputCoins(paymentInfos []*privacy.PaymentInfo, tokenID *common.Hash) ([]*privacy.CoinV2, error) {
	var err error
	isPRV := (tokenID == nil) || (*tokenID == common.PRVCoinID)
	c := make([]*privacy.CoinV2, len(paymentInfos))

	for i := 0; i < len(paymentInfos); i += 1 {
		if isPRV {
			c[i], err = privacy.NewCoinFromPaymentInfo(paymentInfos[i])
			if err != nil {
				fmt.Printf("TxConversion cannot create new coin unique OTA, got error %v", err)
				return nil, err
			}
		} else {
			createdCACoin, _, err := createUniqueOTACoinCA(paymentInfos[i], tokenID)
			if err != nil {
				fmt.Printf("TxConversion cannot create new CA coin - %v", err)
				return nil, err
			}
			err = createdCACoin.SetPlainTokenID(tokenID)
			if err != nil {
				return nil, err
			}
			c[i] = createdCACoin
		}
	}
	return c, nil
}

func proveConversion(tx *Tx, params *TxConvertVer1ToVer2InitParams) error {
	inputCoins := params.inputCoins
	outputCoins, err := createOutputCoins(params.paymentInfo, params.tokenID)
	if err != nil {
		fmt.Printf("TxConversion cannot get output coins from payment info got error %v", err)
		return err
	}
	lenInputs := len(inputCoins)
	serialnumberWitness := make([]*serialnumbernoprivacy.SNNoPrivacyWitness, lenInputs)
	for i := 0; i < len(inputCoins); i++ {
		/***** Build witness for proving that serial number is derived from the committed derivator *****/
		serialnumberWitness[i] = new(serialnumbernoprivacy.SNNoPrivacyWitness)
		serialnumberWitness[i].Set(inputCoins[i].GetKeyImage(), inputCoins[i].GetPublicKey(),
			inputCoins[i].GetSNDerivator(), new(privacy.Scalar).FromBytesS(*params.senderSK))
	}
	tx.Proof, err = privacy_v2.ProveConversion(inputCoins, outputCoins, serialnumberWitness)
	if err != nil {
		fmt.Printf("Error in privacy_v2.Prove, error %v ", err)
		return err
	}

	// sign tx
	if tx.Sig, tx.SigPubKey, err = tx_generic.SignNoPrivacy(params.senderSK, tx.Hash()[:]); err != nil {
		fmt.Println("error signNoPrivacy", err)
		return utils.NewTransactionErr(utils.SignTxError, err)
	}
	return nil
}

// ================ TX TOKEN CONVERSION =================

type CustomTokenConversionParams struct {
	tokenID       *common.Hash
	tokenInputs   []privacy.PlainCoin
	tokenPayments []*privacy.PaymentInfo
}

type TxTokenConvertVer1ToVer2InitParams struct {
	senderSK      *privacy.PrivateKey
	feeInputs     []privacy.PlainCoin
	feePayments   []*privacy.PaymentInfo
	fee           uint64
	tokenParams   *CustomTokenConversionParams
	metaData      metadata.Metadata
	info          []byte // 512 bytes
	kvargs		  map[string]interface{}
}

func NewTxTokenConvertVer1ToVer2InitParams(senderSK *privacy.PrivateKey,
	feeInputs []privacy.PlainCoin,
	feePayments []*privacy.PaymentInfo,
	tokenInputs []privacy.PlainCoin,
	tokenPayments []*privacy.PaymentInfo,
	fee uint64,
	tokenID *common.Hash, // tokenID of the conversion coin
	metaData metadata.Metadata,
	info []byte,
	kvargs map[string]interface{}) *TxTokenConvertVer1ToVer2InitParams {

	if info == nil{
		info = []byte{}
	}


	tokenParams := &CustomTokenConversionParams{
		tokenID:       tokenID,
		tokenPayments: tokenPayments,
		tokenInputs:   tokenInputs,
	}
	return  &TxTokenConvertVer1ToVer2InitParams{
		feeInputs:   feeInputs,
		fee:         fee,
		tokenParams: tokenParams,
		metaData:    metaData,
		feePayments: feePayments,
		senderSK:    senderSK,
		info:        info,
		kvargs: 	 kvargs,
	}
}

func validateTxTokenConvertVer1ToVer2Params (params *TxTokenConvertVer1ToVer2InitParams) error {
	if len(params.feeInputs) > 255 {
		return errors.New("FeeInput is too large, feeInputs length = " + strconv.Itoa(len(params.feeInputs)))
	}
	if len(params.feePayments) > 255 {
		return errors.New("FeePayment is too large, feePayments length = " + strconv.Itoa(len(params.feePayments)))
	}
	if len(params.tokenParams.tokenPayments) > 255 {
		return errors.New("tokenPayments is too large, tokenPayments length = " + strconv.Itoa(len(params.tokenParams.tokenPayments)))
	}
	if len(params.tokenParams.tokenInputs) > 255 {
		return errors.New("tokenInputs length = " + strconv.Itoa(len(params.tokenParams.tokenInputs)))
	}

	for _, c := range params.feeInputs {
		if c.GetVersion() != utils.TxVersion2Number {
			return errors.New("TxConversion should only have fee input coins version 2")
		}
	}
	tokenParams := params.tokenParams
	if tokenParams.tokenID == nil {
		return utils.NewTransactionErr(utils.TokenIDInvalidError, errors.New("TxTokenConversion should have its tokenID not null"))
	}
	sumInput := uint64(0)
	for _, c := range tokenParams.tokenInputs {
		sumInput += c.GetValue()
	}
	if sumInput != tokenParams.tokenPayments[0].Amount {
		return utils.NewTransactionErr(utils.SumInputCoinsAndOutputCoinsError, errors.New("sumInput and sum TokenPayment amount is not equal"))
	}
	return nil
}

func (txToken *TxToken) initTokenConversion(txNormal *Tx, params *TxTokenConvertVer1ToVer2InitParams) error {
	txToken.TokenData.Type = utils.CustomTokenTransfer
	txToken.TokenData.PropertyName = ""
	txToken.TokenData.PropertySymbol = ""
	txToken.TokenData.Mintable = false
	txToken.TokenData.PropertyID = *params.tokenParams.tokenID


	txConvertParams := NewTxConvertVer1ToVer2InitParams(
		params.senderSK,
		params.tokenParams.tokenPayments,
		params.tokenParams.tokenInputs,
		0,
		params.tokenParams.tokenID,
		nil,
		params.info,
		params.kvargs)

	if err := validateTxConvertVer1ToVer2Params(txConvertParams); err != nil {
		return utils.NewTransactionErr(utils.PrivacyTokenInitTokenDataError, err)
	}
	if err := initializeTxConversion(txNormal, txConvertParams); err != nil {
		return utils.NewTransactionErr(utils.PrivacyTokenInitTokenDataError, err)
	}
	txNormal.SetType(common.TxTokenConversionType)
	if err := proveConversion(txNormal, txConvertParams); err != nil {
		return utils.NewTransactionErr(utils.PrivacyTokenInitTokenDataError, err)
	}
	// if err := InitConversion(txNormal, txConvertParams); err != nil {
	// 	return utils.NewTransactionErr(utils.PrivacyTokenInitTokenDataError, err)
	// }
	err := txToken.SetTxNormal(txNormal)
	return err
}

func (txToken *TxToken) initPRVFeeConversion(feeTx *Tx, params *tx_generic.TxPrivacyInitParams) ([]privacy.PlainCoin, []*privacy.CoinV2, error) {
	// txTokenDataHash, err := txToken.TokenData.Hash()
	// if err != nil {
	// 	fmt.Printf("Cannot calculate txPrivacyTokenData Hash, err %v", err)
	// 	return err
	// }
	feeTx.SetVersion(utils.TxConversionVersion12Number)
	feeTx.SetType(common.TxTokenConversionType)
	inps, outs, err := feeTx.provePRV(params)
	if err != nil {
		return nil, nil, utils.NewTransactionErr(utils.PrivacyTokenInitPRVError, err)
	}
	// override TxCustomTokenPrivacyType type

	// txToken.SetTxBase(feeTx)
	return inps, outs, nil
}

func InitTokenConversion(txToken *TxToken, params *TxTokenConvertVer1ToVer2InitParams) error {
	if err := validateTxTokenConvertVer1ToVer2Params(params); err != nil {
		return err
	}

	txPrivacyParams := tx_generic.NewTxPrivacyInitParams(
		params.senderSK, params.feePayments, params.feeInputs, params.fee,
		false, nil, params.metaData, params.info, params.kvargs)
	if err := tx_generic.ValidateTxParams(txPrivacyParams); err != nil {
		return err
	}
	// Init tx and params (tx and params will be changed)
	tx := new(Tx)
	if err := tx.InitializeTxAndParams(txPrivacyParams); err != nil {
		return err
	}

	// Init PRV Fee
	inps, outs, err := txToken.initPRVFeeConversion(tx, txPrivacyParams)
	if err != nil {
		fmt.Printf("Cannot init token ver2: err %v", err)
		return err
	}
	txn := makeTxToken(tx, nil, nil, nil)
	// Init Token
	if err := txToken.initTokenConversion(txn, params); err != nil {
		fmt.Printf("Cannot init token ver2: err %v", err)
		return err
	}
	tdh, err := txToken.TokenData.Hash()
	if err!=nil{
		return err
	}
	message := common.HashH(append(tx.Hash()[:], tdh[:]...))
	err = tx.signOnMessage(inps, outs, txPrivacyParams, message[:])
	if err!=nil{
		return err
	}
	err = txToken.SetTxBase(tx)
	if err!=nil{
		return err
	}
	txSize := txToken.GetTxActualSize()
	if txSize > common.MaxTxSize {
		return utils.NewTransactionErr(utils.ExceedSizeTx, nil, strconv.Itoa(int(txSize)))
	}
	return nil
}


