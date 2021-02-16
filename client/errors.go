package client

import (
	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/solana/token"
	"github.com/kinecosystem/go/xdr"
	"github.com/pkg/errors"

	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"
	commonpbv4 "github.com/kinecosystem/agora-api/genproto/common/v4"
)

var (
	// Query errors.
	ErrAccountExists       = errors.New("account already exists")
	ErrAccountDoesNotExist = errors.New("account does not exist")
	ErrTransactionNotFound = errors.New("transaction not found")

	// Transaction errors.
	ErrBadNonce                = errors.New("bad nonce")
	ErrInsufficientBalance     = errors.New("insufficient balance")
	ErrInvalidSignature        = errors.New("invalid signature")

	// Invoice Errors
	ErrAlreadyPaid      = errors.New("invoice already paid")
	ErrWrongDestination = errors.New("wrong destination")
	ErrSKUNotFound      = errors.New("sku not found")

	ErrNoSubsidizer        = errors.New("no subsidizer available")
	ErrPayerRequired       = errors.New("payer required")
	ErrTransactionRejected = errors.New("transaction rejected")
	ErrAlreadySubmitted    = errors.New("transaction already submitted")

	ErrBlockchainVersion = errors.New("unsupported blockchain version")

	errNoTokenAccounts  = errors.New("no token accounts")

	// nonRetriableErrors contains the set of errors that
	// should not be retried without modifications to the
	// transaction.
	nonRetriableErrors = []error{
		ErrAccountExists,
		ErrAccountDoesNotExist,
		ErrBadNonce,
		ErrInsufficientBalance,
		ErrTransactionNotFound,
		ErrAlreadyPaid,
		ErrWrongDestination,
		ErrSKUNotFound,
		ErrNoSubsidizer,
		ErrPayerRequired,
		ErrTransactionRejected,
		ErrAlreadySubmitted,
		ErrBlockchainVersion,
	}
)

// TransactionErrors contains the error details for a transaction.
// If TxError is non-nil, the transaction failed.
type TransactionErrors struct {
	TxError error

	// OpErrors may or may not be set if TxErrors is set. The length of
	// OpErrors will match the number of operations/instructions in the transaction.
	OpErrors []error

	// PaymentErrors may or may not be set if TxErrors is set. If set, the length of
	// PaymentErrors will match the number of payments/transfers in the transaction.
	PaymentErrors []error
}

func errorsFromSolanaTx(tx *solana.Transaction, protoError *commonpbv4.TransactionError) (txErrors TransactionErrors) {
	e := errorFromProto(protoError)
	if e == nil {
		return txErrors
	}

	txErrors.TxError = e
	if protoError.GetInstructionIndex() >= 0 {
		txErrors.OpErrors = make([]error, len(tx.Message.Instructions))
		txErrors.OpErrors[protoError.GetInstructionIndex()] = e

		paymentErrIndex := protoError.GetInstructionIndex()
		paymentCount := 0

		for i := range tx.Message.Instructions {
			_, err := token.DecompileTransferAccount(tx.Message, i)
			if err == nil {
				paymentCount++
			} else if i < int(protoError.GetInstructionIndex()) {
				paymentErrIndex--
			} else if i == int(protoError.GetInstructionIndex()) {
				paymentErrIndex = -1
			}
		}

		if paymentErrIndex > -1 {
			txErrors.PaymentErrors = make([]error, paymentCount)
			txErrors.PaymentErrors[paymentErrIndex] = e
		}
	}

	return txErrors
}

func errorsFromStellarTx(env xdr.TransactionEnvelope, protoError *commonpbv4.TransactionError) (txErrors TransactionErrors) {
	e := errorFromProto(protoError)
	if e == nil {
		return txErrors
	}

	txErrors.TxError = e
	if protoError.GetInstructionIndex() >= 0 {
		txErrors.OpErrors = make([]error, len(env.Tx.Operations))
		txErrors.OpErrors[protoError.GetInstructionIndex()] = e

		paymentErrIndex := protoError.GetInstructionIndex()
		paymentCount := 0
		for i, op := range env.Tx.Operations {
			if op.Body.Type == xdr.OperationTypePayment {
				paymentCount++
			} else if i < int(protoError.GetInstructionIndex()) {
				paymentErrIndex--
			} else if i == int(protoError.GetInstructionIndex()) {
				paymentErrIndex = -1
			}
		}

		if paymentErrIndex > -1 {
			txErrors.PaymentErrors = make([]error, paymentCount)
			txErrors.PaymentErrors[paymentErrIndex] = e
		}
	}

	return txErrors
}

func errorFromProto(protoError *commonpbv4.TransactionError) error {
	if protoError == nil {
		return nil
	}

	switch protoError.Reason {
	case commonpbv4.TransactionError_NONE:
		return nil
	case commonpbv4.TransactionError_UNKNOWN:
		return errors.New("unknown error")
	case commonpbv4.TransactionError_UNAUTHORIZED:
		return ErrInvalidSignature
	case commonpbv4.TransactionError_BAD_NONCE:
		return ErrBadNonce
	case commonpbv4.TransactionError_INSUFFICIENT_FUNDS:
		return ErrInsufficientBalance
	case commonpbv4.TransactionError_INVALID_ACCOUNT:
		return ErrAccountDoesNotExist
	default:
		return errors.Errorf("unknown error reason: %d", protoError.Reason)
	}
}

func invoiceErrorFromProto(protoError *commonpb.InvoiceError) error {
	if protoError == nil {
		return nil
	}

	switch protoError.Reason {
	case commonpb.InvoiceError_ALREADY_PAID:
		return ErrAlreadyPaid
	case commonpb.InvoiceError_WRONG_DESTINATION:
		return ErrWrongDestination
	case commonpb.InvoiceError_SKU_NOT_FOUND:
		return ErrSKUNotFound
	default:
		return errors.Errorf("unknown invoice error: %v", protoError.Reason)
	}
}
