package debugtool

import (
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/metadata"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/wallet"
)

func CreatePDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	pdeTradeMetadata, err := metadata.NewPDETradeRequest(tokenIDToBuy, tokenIDToSell, amount, 0, 0,
		addr, "", metadata.PDETradeRequestMeta)

	return CreateRawTransaction(privateKey, []string{common.BurningAddress2}, []uint64{amount}, 1, pdeTradeMetadata)
}

func CreateAndSendPDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy string, amount uint64) (string, error) {
	encodedTx, txHash, err := CreatePDETradeTransaction(privateKey, tokenIDToSell, tokenIDToBuy, amount)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTx(string(encodedTx))
	if err != nil {
		return "", err
	}

	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

func CreatePDEContributeTransaction(privateKey, pairID, tokenID string, amount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	md, err := metadata.NewPDEContribution(pairID, addr, amount, tokenID, metadata.PDEContributionMeta)

	if tokenID == common.PRVIDStr {
		return CreateRawTransaction(privateKey, []string{common.BurningAddress2}, []uint64{amount}, 1, md)
	} else {
		return CreateRawTokenTransaction(privateKey, []string{common.BurningAddress2}, []uint64{amount}, 1, tokenID, 1, md)
	}
}

func CreateAndSendPDEContributeTransaction(privateKey, pairID, tokenID string, amount uint64) (string, error) {
	encodedTx, txHash, err := CreatePDEContributeTransaction(privateKey, pairID, tokenID, amount)
	if err != nil {
		return "", err
	}

	var responseInBytes []byte
	if tokenID == common.PRVIDStr {
		responseInBytes, err = rpc.SendRawTx(string(encodedTx))
		if err != nil {
			return "", err
		}
	} else {
		responseInBytes, err = rpc.SendRawTokenTx(string(encodedTx))
		if err != nil {
			return "", err
		}
	}


	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}

func CreatePDEWithdrawalTransaction(privateKey, tokenID1, tokenID2 string, sharedAmount uint64) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	addr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	pdeTradeMetadata, err := metadata.NewPDEWithdrawalRequest(addr, tokenID2, tokenID1, sharedAmount, metadata.PDEWithdrawalRequestMeta)

	return CreateRawTransaction(privateKey, []string{}, []uint64{}, 1, pdeTradeMetadata)
}

func CreateAndSendPDEWithdrawalTransaction(privateKey, tokenID1, tokenID2 string, sharedAmount uint64) (string, error) {
	encodedTx, txHash, err := CreatePDEWithdrawalTransaction(privateKey, tokenID1, tokenID2, sharedAmount)
	if err != nil {
		return "", err
	}

	responseInBytes, err := rpc.SendRawTx(string(encodedTx))
	if err != nil {
		return "", err
	}

	_, err = rpchandler.ParseResponse(responseInBytes)
	if err != nil {
		return "", err
	}

	return txHash, nil
}
