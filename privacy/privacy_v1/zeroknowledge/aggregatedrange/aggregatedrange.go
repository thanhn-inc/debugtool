package aggregatedrange

import (
	"fmt"
	"github.com/pkg/errors"
	errhandler "github.com/thanhn-inc/debugtool/privacy/errorhandler"
	"github.com/thanhn-inc/debugtool/privacy/operation"
	"github.com/thanhn-inc/debugtool/privacy/privacy_v1/zeroknowledge/aggregatedrange/bulletproofs"
)

// This protocol proves in zero-knowledge that a list of committed values falls in [0, 2^64)

type AggregatedRangeWitness struct {
	values []uint64
	rands  []*operation.Scalar
}

type AggregatedRangeProof struct {
	cmsValue          []*operation.Point
	a                 *operation.Point
	s                 *operation.Point
	t1                *operation.Point
	t2                *operation.Point
	tauX              *operation.Scalar
	tHat              *operation.Scalar
	mu                *operation.Scalar
	innerProductProof *InnerProductProof
}

func (proof AggregatedRangeProof) ValidateSanity() bool {
	for i := 0; i < len(proof.cmsValue); i++ {
		if !proof.cmsValue[i].PointValid() {
			return false
		}
	}
	if !proof.a.PointValid() {
		return false
	}
	if !proof.s.PointValid() {
		return false
	}
	if !proof.t1.PointValid() {
		return false
	}
	if !proof.t2.PointValid() {
		return false
	}
	if !proof.tauX.ScalarValid() {
		return false
	}
	if !proof.tHat.ScalarValid() {
		return false
	}
	if !proof.mu.ScalarValid() {
		return false
	}

	return proof.innerProductProof.ValidateSanity()
}

func (proof *AggregatedRangeProof) Init() {
	proof.a = new(operation.Point).Identity()
	proof.s = new(operation.Point).Identity()
	proof.t1 = new(operation.Point).Identity()
	proof.t2 = new(operation.Point).Identity()
	proof.tauX = new(operation.Scalar)
	proof.tHat = new(operation.Scalar)
	proof.mu = new(operation.Scalar)
	proof.innerProductProof = new(InnerProductProof)
}

func (proof AggregatedRangeProof) IsNil() bool {
	if proof.a == nil {
		return true
	}
	if proof.s == nil {
		return true
	}
	if proof.t1 == nil {
		return true
	}
	if proof.t2 == nil {
		return true
	}
	if proof.tauX == nil {
		return true
	}
	if proof.tHat == nil {
		return true
	}
	if proof.mu == nil {
		return true
	}
	return proof.innerProductProof == nil
}

func (proof AggregatedRangeProof) Bytes() []byte {
	var res []byte

	if proof.IsNil() {
		return []byte{}
	}

	res = append(res, byte(len(proof.cmsValue)))
	for i := 0; i < len(proof.cmsValue); i++ {
		res = append(res, proof.cmsValue[i].ToBytesS()...)
	}

	res = append(res, proof.a.ToBytesS()...)
	res = append(res, proof.s.ToBytesS()...)
	res = append(res, proof.t1.ToBytesS()...)
	res = append(res, proof.t2.ToBytesS()...)

	res = append(res, proof.tauX.ToBytesS()...)
	res = append(res, proof.tHat.ToBytesS()...)
	res = append(res, proof.mu.ToBytesS()...)
	res = append(res, proof.innerProductProof.Bytes()...)

	return res

}

func (proof AggregatedRangeProof) GetCommitments() []*operation.Point {
	return proof.cmsValue
}

func (proof AggregatedRangeProof) SetCommitments(cmsValue []*operation.Point) {
	proof.cmsValue = cmsValue
}

func (proof *AggregatedRangeProof) SetBytes(bytes []byte) error {
	if len(bytes) == 0 {
		return nil
	}

	lenValues := int(bytes[0])
	offset := 1
	var err error

	proof.cmsValue = make([]*operation.Point, lenValues)
	for i := 0; i < lenValues; i++ {
		if offset + operation.Ed25519KeySize > len(bytes) {
			return errors.New("Not enough bytes to unmarshal Aggregated Range Proof")
		}
		proof.cmsValue[i], err = new(operation.Point).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
		if err != nil {
			return err
		}
		offset += operation.Ed25519KeySize
	}

	if offset + 7*operation.Ed25519KeySize > len(bytes) {
		return errors.New("Not enough bytes to unmarshal Aggregated Range Proof")
	}
	proof.a, err = new(operation.Point).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += operation.Ed25519KeySize

	proof.s, err = new(operation.Point).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += operation.Ed25519KeySize

	proof.t1, err = new(operation.Point).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += operation.Ed25519KeySize

	proof.t2, err = new(operation.Point).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
	if err != nil {
		return err
	}
	offset += operation.Ed25519KeySize

	proof.tauX = new(operation.Scalar).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
	offset += operation.Ed25519KeySize

	proof.tHat = new(operation.Scalar).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
	offset += operation.Ed25519KeySize

	proof.mu = new(operation.Scalar).FromBytesS(bytes[offset : offset+operation.Ed25519KeySize])
	offset += operation.Ed25519KeySize

	proof.innerProductProof = new(InnerProductProof)
	err = proof.innerProductProof.SetBytes(bytes[offset:])

	//Logger.Log.Debugf("AFTER SETBYTES ------------ %v\n", proof.Bytes())
	return err
}

func (wit *AggregatedRangeWitness) Set(values []uint64, rands []*operation.Scalar) {
	numValue := len(values)
	wit.values = make([]uint64, numValue)
	wit.rands = make([]*operation.Scalar, numValue)

	for i := range values {
		wit.values[i] = values[i]
		wit.rands[i] = new(operation.Scalar).Set(rands[i])
	}
}

func (wit AggregatedRangeWitness) Prove() (*AggregatedRangeProof, error) {
	wit2 := new(bulletproofs.AggregatedRangeWitness)
	wit2.Set(wit.values, wit.rands)

	proof2, err := wit2.Prove()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot prove bulletproof v2. Error %v", err))
	}
	proof2Bytes := proof2.Bytes()
	proof := new(AggregatedRangeProof)
	err = proof.SetBytes(proof2Bytes)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, errors.New(fmt.Sprintf("cannot convert proof ver 2  to ver 1. Error %v", err))
	}
	return proof, nil
}

func (proof AggregatedRangeProof) VerifyOld() (bool, error) {
	numValue := len(proof.cmsValue)
	if numValue > maxOutputNumber {
		return false, errors.New("Must less than maxOutputNumber")
	}
	numValuePad := pad(numValue)
	aggParam := new(bulletproofParams)
	aggParam.g = AggParam.g[0 : numValuePad*maxExp]
	aggParam.h = AggParam.h[0 : numValuePad*maxExp]
	aggParam.u = AggParam.u
	csByteH := []byte{}
	csByteG := []byte{}
	for i := 0; i < len(aggParam.g); i++ {
		csByteG = append(csByteG, aggParam.g[i].ToBytesS()...)
		csByteH = append(csByteH, aggParam.h[i].ToBytesS()...)
	}
	aggParam.cs = append(aggParam.cs, csByteG...)
	aggParam.cs = append(aggParam.cs, csByteH...)
	aggParam.cs = append(aggParam.cs, aggParam.u.ToBytesS()...)

	tmpcmsValue := proof.cmsValue

	for i := numValue; i < numValuePad; i++ {
		identity := new(operation.Point).Identity()
		tmpcmsValue = append(tmpcmsValue, identity)
	}

	n := maxExp
	oneNumber := new(operation.Scalar).FromUint64(1)
	twoNumber := new(operation.Scalar).FromUint64(2)
	oneVector := powerVector(oneNumber, n*numValuePad)
	oneVectorN := powerVector(oneNumber, n)
	twoVectorN := powerVector(twoNumber, n)

	// recalculate challenge y, z
	y := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS()})
	z := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), y.ToBytesS()})
	zSquare := new(operation.Scalar).Mul(z, z)

	// challenge x = hash(G || H || A || S || T1 || T2)
	//fmt.Printf("T2: %v\n", proof.t2)
	x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), proof.t1.ToBytesS(), proof.t2.ToBytesS()})
	xSquare := new(operation.Scalar).Mul(x, x)

	yVector := powerVector(y, n*numValuePad)
	// HPrime = H^(y^(1-i)
	HPrime := make([]*operation.Point, n*numValuePad)
	yInverse := new(operation.Scalar).Invert(y)
	expyInverse := new(operation.Scalar).FromUint64(1)
	for i := 0; i < n*numValuePad; i++ {
		HPrime[i] = new(operation.Point).ScalarMult(aggParam.h[i], expyInverse)
		expyInverse.Mul(expyInverse, yInverse)
	}

	// g^tHat * h^tauX = V^(z^2) * g^delta(y,z) * T1^x * T2^(x^2)
	deltaYZ := new(operation.Scalar).Sub(z, zSquare)

	// innerProduct1 = <1^(n*m), y^(n*m)>
	innerProduct1, err := innerProduct(oneVector, yVector)
	if err != nil {
		return false, errhandler.NewPrivacyErr(errhandler.CalInnerProductErr, err)
	}

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2, err := innerProduct(oneVectorN, twoVectorN)
	if err != nil {
		return false, errhandler.NewPrivacyErr(errhandler.CalInnerProductErr, err)
	}

	sum := new(operation.Scalar).FromUint64(0)
	zTmp := new(operation.Scalar).Set(zSquare)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		sum.Add(sum, zTmp)
	}
	sum.Mul(sum, innerProduct2)
	deltaYZ.Sub(deltaYZ, sum)

	left1 := operation.PedCom.CommitAtIndex(proof.tHat, proof.tauX, operation.PedersenValueIndex)

	right1 := new(operation.Point).ScalarMult(proof.t2, xSquare)
	right1.Add(right1, new(operation.Point).AddPedersen(deltaYZ, operation.PedCom.G[operation.PedersenValueIndex], x, proof.t1))

	expVector := vectorMulScalar(powerVector(z, numValuePad), zSquare)
	right1.Add(right1, new(operation.Point).MultiScalarMult(expVector, tmpcmsValue))

	if !operation.IsPointEqual(left1, right1) {
		fmt.Printf("verify aggregated range proof statement 1 failed")

		////TODO Remove later ...
		//fmt.Println("[BUGLOG SKIP TX] Skip Fail Tx to Test")
		//return true, nil
		////END TODO

		return false, errors.New("verify aggregated range proof statement 1 failed")
	}

	innerProductArgValid := proof.innerProductProof.Verify(aggParam)
	if !innerProductArgValid {
		fmt.Printf("verify aggregated range proof statement 2 failed")
		return false, errors.New("verify aggregated range proof statement 2 failed")
	}

	return true, nil
}

func (proof AggregatedRangeProof) Verify() (bool, error) {
	proof2 := new(bulletproofs.AggregatedRangeProof)
	err := proof2.SetBytes(proof.Bytes())
	if err != nil {
		return false, errors.New(fmt.Sprintf("cannot convert proof from v1 to v2. Error %v", err))
	}
	return proof2.VerifyFaster()
}

func VerifyBatchOld (proofs []*AggregatedRangeProof) (bool, error, int) {
	innerProductProofs := make([]*InnerProductProof, 0)
	csList := make([][]byte, 0)
	for k, proof := range proofs {
		numValue := len(proof.cmsValue)
		if numValue > maxOutputNumber {
			return false, errors.New("Must less than maxOutputNumber"), k
		}
		numValuePad := pad(numValue)
		aggParam := new(bulletproofParams)
		aggParam.g = AggParam.g[0 : numValuePad*maxExp]
		aggParam.h = AggParam.h[0 : numValuePad*maxExp]
		aggParam.u = AggParam.u
		csByteH := []byte{}
		csByteG := []byte{}
		for i := 0; i < len(aggParam.g); i++ {
			csByteG = append(csByteG, aggParam.g[i].ToBytesS()...)
			csByteH = append(csByteH, aggParam.h[i].ToBytesS()...)
		}
		aggParam.cs = append(aggParam.cs, csByteG...)
		aggParam.cs = append(aggParam.cs, csByteH...)
		aggParam.cs = append(aggParam.cs, aggParam.u.ToBytesS()...)

		tmpcmsValue := proof.cmsValue

		for i := numValue; i < numValuePad; i++ {
			identity := new(operation.Point).Identity()
			tmpcmsValue = append(tmpcmsValue, identity)
		}

		n := maxExp
		oneNumber := new(operation.Scalar).FromUint64(1)
		twoNumber := new(operation.Scalar).FromUint64(2)
		oneVector := powerVector(oneNumber, n*numValuePad)
		oneVectorN := powerVector(oneNumber, n)
		twoVectorN := powerVector(twoNumber, n)

		// recalculate challenge y, z
		y := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS()})
		z := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), y.ToBytesS()})
		zSquare := new(operation.Scalar).Mul(z, z)

		// challenge x = hash(G || H || A || S || T1 || T2)
		//fmt.Printf("T2: %v\n", proof.t2)
		x := generateChallenge([][]byte{aggParam.cs, proof.a.ToBytesS(), proof.s.ToBytesS(), proof.t1.ToBytesS(), proof.t2.ToBytesS()})
		xSquare := new(operation.Scalar).Mul(x, x)

		yVector := powerVector(y, n*numValuePad)
		// HPrime = H^(y^(1-i)
		HPrime := make([]*operation.Point, n*numValuePad)
		yInverse := new(operation.Scalar).Invert(y)
		expyInverse := new(operation.Scalar).FromUint64(1)
		for i := 0; i < n*numValuePad; i++ {
			HPrime[i] = new(operation.Point).ScalarMult(aggParam.h[i], expyInverse)
			expyInverse.Mul(expyInverse, yInverse)
		}

		// g^tHat * h^tauX = V^(z^2) * g^delta(y,z) * T1^x * T2^(x^2)
		deltaYZ := new(operation.Scalar).Sub(z, zSquare)

		// innerProduct1 = <1^(n*m), y^(n*m)>
		innerProduct1, err := innerProduct(oneVector, yVector)
		if err != nil {
			return false, errhandler.NewPrivacyErr(errhandler.CalInnerProductErr, err), k
		}

		deltaYZ.Mul(deltaYZ, innerProduct1)

		// innerProduct2 = <1^n, 2^n>
		innerProduct2, err := innerProduct(oneVectorN, twoVectorN)
		if err != nil {
			return false, errhandler.NewPrivacyErr(errhandler.CalInnerProductErr, err), k
		}

		sum := new(operation.Scalar).FromUint64(0)
		zTmp := new(operation.Scalar).Set(zSquare)
		for j := 0; j < numValuePad; j++ {
			zTmp.Mul(zTmp, z)
			sum.Add(sum, zTmp)
		}
		sum.Mul(sum, innerProduct2)
		deltaYZ.Sub(deltaYZ, sum)

		left1 := operation.PedCom.CommitAtIndex(proof.tHat, proof.tauX, operation.PedersenValueIndex)

		right1 := new(operation.Point).ScalarMult(proof.t2, xSquare)
		right1.Add(right1, new(operation.Point).AddPedersen(deltaYZ, operation.PedCom.G[operation.PedersenValueIndex], x, proof.t1))

		expVector := vectorMulScalar(powerVector(z, numValuePad), zSquare)
		right1.Add(right1, new(operation.Point).MultiScalarMult(expVector, tmpcmsValue))

		if !operation.IsPointEqual(left1, right1) {
			fmt.Printf("verify aggregated range proof statement 1 failed index %d", k)
			return false, fmt.Errorf("verify aggregated range proof statement 1 failed index %d", k), k
		}

		innerProductProofs = append(innerProductProofs, proof.innerProductProof)
		csList = append(csList, aggParam.cs)
	}

	innerProductArgsValid := VerifyBatchingInnerProductProofs(innerProductProofs, csList)
	if !innerProductArgsValid {
		fmt.Printf("verify batch aggregated range proofs statement 2 failed")
		return false, errors.New("verify batch aggregated range proofs statement 2 failed"), -1
	}

	return true, nil, -1
}

func VerifyBatch(proofs []*AggregatedRangeProof) (bool, error, int) {
	proofs2 := make([]*bulletproofs.AggregatedRangeProof, len(proofs))
	for i, proof := range proofs {
		proofs2[i] = new(bulletproofs.AggregatedRangeProof)
		err := proofs2[i].SetBytes(proof.Bytes())
		if err != nil {
			return false, errors.New(fmt.Sprintf("cannot convert proof from v1 to v2. Error %v", err)), i
		}
	}
	return bulletproofs.VerifyBatch(proofs2)
}