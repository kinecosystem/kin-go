package testutil

import (
	"bytes"
	"crypto/ed25519"
	"sort"
	"testing"

	"github.com/kinecosystem/go/keypair"
	"github.com/kinecosystem/go/strkey"
	"github.com/pkg/errors"
	"github.com/stellar/go/xdr"
	"github.com/stretchr/testify/require"
)

func StellarAccountIDFromString(address string) (id xdr.AccountId, err error) {
	k, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return id, errors.New("failed to decode provided address")
	}
	var v xdr.Uint256
	copy(v[:], k)
	return xdr.AccountId{
		Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
		Ed25519: &v,
	}, nil
}

func GenerateAccountID(t *testing.T) (*keypair.Full, xdr.AccountId) {
	kp, err := keypair.Random()
	require.NoError(t, err)

	pubKey, err := strkey.Decode(strkey.VersionByteAccountID, kp.Address())
	require.NoError(t, err)
	var senderPubKey xdr.Uint256
	copy(senderPubKey[:], pubKey)

	return kp, xdr.AccountId{
		Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
		Ed25519: &senderPubKey,
	}
}

func GenerateAccountIDs(t *testing.T, n int) []xdr.AccountId {
	accounts := make([]xdr.AccountId, n)
	for i := 0; i < n; i++ {
		_, accountID := GenerateAccountID(t)
		accounts[i] = accountID
	}
	return accounts
}

func SortKeys(src []ed25519.PublicKey) {
	sort.Slice(src, func(i, j int) bool { return bytes.Compare(src[i], src[j]) < 0 })
}

func GenerateTransactionEnvelope(src xdr.AccountId, seqNum int, operations []xdr.Operation) xdr.TransactionEnvelope {
	return xdr.TransactionEnvelope{
		Tx: xdr.Transaction{
			SourceAccount: src,
			SeqNum:        xdr.SequenceNumber(seqNum),
			Operations:    operations,
		},
	}
}

func GenerateCreateOperation(src *xdr.AccountId, dest xdr.AccountId) xdr.Operation {
	return xdr.Operation{
		SourceAccount: src,
		Body: xdr.OperationBody{
			Type:            xdr.OperationTypeCreateAccount,
			CreateAccountOp: &xdr.CreateAccountOp{Destination: dest},
		},
	}
}

func GeneratePaymentOperation(src *xdr.AccountId, dest xdr.AccountId) xdr.Operation {
	return xdr.Operation{
		SourceAccount: src,
		Body: xdr.OperationBody{
			Type: xdr.OperationTypePayment,
			PaymentOp: &xdr.PaymentOp{
				Destination: dest,
				Amount:      10,
			},
		},
	}
}

func GenerateKin2PaymentOperation(src *xdr.AccountId, dest xdr.AccountId, issuer xdr.AccountId) xdr.Operation {
	assetCode := [4]byte{}
	copy(assetCode[:], "KIN")

	return xdr.Operation{
		SourceAccount: src,
		Body: xdr.OperationBody{
			Type: xdr.OperationTypePayment,
			PaymentOp: &xdr.PaymentOp{
				Destination: dest,
				Amount:      1000, // equivalent to 10 quarks
				Asset: xdr.Asset{
					Type: xdr.AssetTypeAssetTypeCreditAlphanum4,
					AlphaNum4: &xdr.AssetAlphaNum4{
						AssetCode: assetCode,
						Issuer:    issuer,
					},
				},
			},
		},
	}
}
