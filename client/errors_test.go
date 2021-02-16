package client

import (
	"testing"

	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/solana/memo"
	"github.com/kinecosystem/agora-common/solana/token"
	"github.com/kinecosystem/go/xdr"
	stellarxdr "github.com/stellar/go/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"
	commonpbv4 "github.com/kinecosystem/agora-api/genproto/common/v4"

	"github.com/kinecosystem/kin-go/client/testutil"
)

func TestErrorFromProto(t *testing.T) {
	for _, tc := range []struct {
		reason  commonpbv4.TransactionError_Reason
		txError error
	}{
		{
			reason:  commonpbv4.TransactionError_NONE,
			txError: nil,
		},
		{
			reason:  commonpbv4.TransactionError_UNAUTHORIZED,
			txError: ErrInvalidSignature,
		},
		{
			reason:  commonpbv4.TransactionError_BAD_NONCE,
			txError: ErrBadNonce,
		},
		{
			reason:  commonpbv4.TransactionError_INSUFFICIENT_FUNDS,
			txError: ErrInsufficientBalance,
		},
		{
			reason:  commonpbv4.TransactionError_INVALID_ACCOUNT,
			txError: ErrAccountDoesNotExist,
		},
	} {
		err := errorFromProto(&commonpbv4.TransactionError{Reason: tc.reason})
		assert.Equal(t, tc.txError, err)
	}

	// Unknown error
	err := errorFromProto(&commonpbv4.TransactionError{Reason: commonpbv4.TransactionError_UNKNOWN})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestInvoiceErrorFromProto(t *testing.T) {
	for _, tc := range []struct {
		reason  commonpb.InvoiceError_Reason
		txError error
	}{
		{
			reason:  commonpb.InvoiceError_ALREADY_PAID,
			txError: ErrAlreadyPaid,
		},
		{
			reason:  commonpb.InvoiceError_WRONG_DESTINATION,
			txError: ErrWrongDestination,
		},
		{
			reason:  commonpb.InvoiceError_SKU_NOT_FOUND,
			txError: ErrSKUNotFound,
		},
	} {
		err := invoiceErrorFromProto(&commonpb.InvoiceError{Reason: tc.reason})
		assert.Equal(t, tc.txError, err)
	}

	// Unknown error
	err := invoiceErrorFromProto(&commonpb.InvoiceError{Reason: commonpb.InvoiceError_UNKNOWN})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestErrorsFromSolanaTx(t *testing.T) {
	keys := testutil.GenerateSolanaKeys(t, 3)
	tx := solana.NewTransaction(
		keys[0],
		memo.Instruction("data"),
		token.Transfer(keys[1], keys[2], keys[1], 100),
		token.SetAuthority(keys[1], keys[1], keys[2], token.AuthorityTypeAccountHolder),
	)

	for _, tc := range []struct {
		instructionIndex int32
		expOpIndex       int
		expPaymentIndex  int
	}{
		{
			instructionIndex: 1,
			expOpIndex:       1,
			expPaymentIndex:  0,
		},
		{
			instructionIndex: 0,
			expOpIndex:       0,
			expPaymentIndex:  -1,
		},
	} {
		errors := errorsFromSolanaTx(&tx, &commonpbv4.TransactionError{
			Reason:           commonpbv4.TransactionError_INSUFFICIENT_FUNDS,
			InstructionIndex: tc.instructionIndex,
		})
		assert.Equal(t, ErrInsufficientBalance, errors.TxError)
		assert.Equal(t, 3, len(errors.OpErrors))

		for i := range errors.OpErrors {
			if i == tc.expOpIndex {
				assert.Equal(t, ErrInsufficientBalance, errors.OpErrors[i])
			} else {
				assert.Nil(t, errors.OpErrors[i])
			}
		}

		if tc.expPaymentIndex > -1 {
			assert.Equal(t, 1, len(errors.PaymentErrors))
			for i := range errors.PaymentErrors {
				if i == tc.expPaymentIndex {
					assert.Equal(t, ErrInsufficientBalance, errors.PaymentErrors[i])
				} else {
					assert.Nil(t, errors.PaymentErrors[i])
				}
			}
		} else {
			assert.Nil(t, errors.PaymentErrors)
		}
	}
}

func TestErrorsFromStellarTx(t *testing.T) {
	accountIDs := testutil.GenerateAccountIDs(t, 3)
	ops := []stellarxdr.Operation{
		testutil.GenerateCreateOperation(&accountIDs[0], accountIDs[1]),
		testutil.GeneratePaymentOperation(&accountIDs[0], accountIDs[1]),
		testutil.GeneratePaymentOperation(&accountIDs[0], accountIDs[1]),
		testutil.GenerateCreateOperation(&accountIDs[0], accountIDs[1]),
	}
	// to take advantage of the test utils, marshal the stellarxdr env and unmarshal as a kinecosystem/xdr env
	b, err := testutil.GenerateTransactionEnvelope(accountIDs[2], 10, ops).MarshalBinary()
	require.NoError(t, err)

	var envelope xdr.TransactionEnvelope
	require.NoError(t, envelope.UnmarshalBinary(b))

	for _, tc := range []struct {
		instructionIndex int32
		expOpIndex       int
		expPaymentIndex  int
	}{
		{
			instructionIndex: 2,
			expOpIndex:       2,
			expPaymentIndex:  1,
		},
		{
			instructionIndex: 3,
			expOpIndex:       3,
			expPaymentIndex:  -1,
		},
	} {
		errors := errorsFromStellarTx(envelope, &commonpbv4.TransactionError{
			Reason:           commonpbv4.TransactionError_INSUFFICIENT_FUNDS,
			InstructionIndex: tc.instructionIndex,
		})
		assert.Equal(t, ErrInsufficientBalance, errors.TxError)
		assert.Equal(t, 4, len(errors.OpErrors))

		for i := range errors.OpErrors {
			if i == tc.expOpIndex {
				assert.Equal(t, ErrInsufficientBalance, errors.OpErrors[i])
			} else {
				assert.Nil(t, errors.OpErrors[i])
			}
		}

		if tc.expPaymentIndex > -1 {
			assert.Equal(t, 2, len(errors.PaymentErrors))
			for i := range errors.PaymentErrors {
				if i == tc.expPaymentIndex {
					assert.Equal(t, ErrInsufficientBalance, errors.PaymentErrors[i])
				} else {
					assert.Nil(t, errors.PaymentErrors[i])
				}
			}
		} else {
			assert.Nil(t, errors.PaymentErrors)
		}
	}
}
