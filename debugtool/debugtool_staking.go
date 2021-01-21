package debugtool

import (
	"errors"
	"fmt"
	"github.com/thanhn-inc/debugtool/common"
	"github.com/thanhn-inc/debugtool/common/base58"
	"github.com/thanhn-inc/debugtool/incognitokey"
	"github.com/thanhn-inc/debugtool/metadata"
	"github.com/thanhn-inc/debugtool/rpchandler"
	"github.com/thanhn-inc/debugtool/rpchandler/rpc"
	"github.com/thanhn-inc/debugtool/wallet"
)

func CreateStakingTransaction(privateKey, privateSeed, candidateAddr, rewardReceiverAddr string, autoStack bool) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	funderAddr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	if len(candidateAddr) == 0 {
		candidateAddr = funderAddr
	}
	if len(rewardReceiverAddr) == 0 {
		rewardReceiverAddr = funderAddr
	}

	candidateWallet, err := wallet.Base58CheckDeserialize(candidateAddr)
	if err != nil {
		return nil, "", err
	}
	pk := candidateWallet.KeySet.PaymentAddress.Pk
	if len(pk) == 0 {
		return nil, "", errors.New(fmt.Sprintf("candidate payment address invalid: %v", candidateAddr))
	}

	seed, _, err := base58.Base58Check{}.Decode(privateSeed)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot decode private seed: %v", privateSeed))
	}

	committeePK, err := incognitokey.NewCommitteeKeyFromSeed(seed, pk)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot create committee key from pk: %v, seed: %v. Error: %v", pk, seed, err))
	}

	committeePKBytes, err := committeePK.Bytes()
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("committe to bytes error: %v", err))
	}

	stakingAmount := uint64(1750000000000)

	pdeTradeMetadata, err := metadata.NewStakingMetadata(metadata.ShardStakingMeta, funderAddr, rewardReceiverAddr, stakingAmount,
		base58.Base58Check{}.Encode(committeePKBytes, common.ZeroByte), autoStack)

	return CreateRawTransaction(privateKey, []string{common.BurningAddress2}, []uint64{stakingAmount}, 1, pdeTradeMetadata)
}
func CreateAndSendStakingTransaction(privateKey, privateSeed, candidateAddr, rewardReceiverAddr string, autoStack bool) (string, error) {
	encodedTx, txHash, err := CreateStakingTransaction(privateKey, privateSeed, candidateAddr, rewardReceiverAddr, autoStack)
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

func CreateUnStakingTransaction(privateKey, privateSeed, candidateAddr string) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	funderAddr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	if len(candidateAddr) == 0 {
		candidateAddr = funderAddr
	}

	candidateWallet, err := wallet.Base58CheckDeserialize(candidateAddr)
	if err != nil {
		return nil, "", err
	}
	pk := candidateWallet.KeySet.PaymentAddress.Pk
	if len(pk) == 0 {
		return nil, "", errors.New(fmt.Sprintf("candidate payment address invalid: %v", candidateAddr))
	}

	seed, _, err := base58.Base58Check{}.Decode(privateSeed)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot decode private seed: %v", privateSeed))
	}

	committeePK, err := incognitokey.NewCommitteeKeyFromSeed(seed, pk)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("cannot create committee key from pk: %v, seed: %v. Error: %v", pk, seed, err))
	}

	committeePKBytes, err := committeePK.Bytes()
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("committe to bytes error: %v", err))
	}

	pdeTradeMetadata, err := metadata.NewStopAutoStakingMetadata(metadata.StopAutoStakingMeta, base58.Base58Check{}.Encode(committeePKBytes, common.ZeroByte))

	return CreateRawTransaction(privateKey, []string{common.BurningAddress2}, []uint64{0}, 1, pdeTradeMetadata)
}
func CreateAndSendUnStakingTransaction(privateKey, privateSeed, candidateAddr string) (string, error) {
	encodedTx, txHash, err := CreateUnStakingTransaction(privateKey, privateSeed, candidateAddr)
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

func CreateWithDrawRewardTransaction(privateKey, addr string) ([]byte, string, error) {
	senderWallet, err := wallet.Base58CheckDeserialize(privateKey)
	if err != nil {
		return nil, "", err
	}

	funderAddr := senderWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	if len(addr) == 0 {
		addr = funderAddr
	}

	pdeTradeMetadata, err := metadata.NewWithDrawRewardRequest(common.PRVIDStr, addr, 1, metadata.WithDrawRewardRequestMeta)

	return CreateRawTransaction(privateKey, []string{}, []uint64{}, 1, pdeTradeMetadata)
}
func CreateAndSendWithDrawRewardTransaction(privateKey, addr string) (string, error) {
	encodedTx, txHash, err := CreateWithDrawRewardTransaction(privateKey, addr)
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