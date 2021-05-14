package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"

	"github.com/golang/protobuf/proto"
	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/solana/memo"
	"github.com/kinecosystem/go/xdr"
	"github.com/pkg/errors"

	accountpbv4 "github.com/kinecosystem/agora-api/genproto/account/v4"
	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"
	transactionpbv4 "github.com/kinecosystem/agora-api/genproto/transaction/v4"
)

type Creation struct {
	Owner   kin.PublicKey
	Address kin.PublicKey
}

// Payment represents a kin payment.
type Payment struct {
	Sender      kin.PrivateKey
	Destination kin.PublicKey
	Type        kin.TransactionType
	Quarks      int64

	Invoice *commonpb.Invoice
	Memo    string

	// DedupeID is a unique identifier used by the service to help prevent the
	// accidental submission of the same intended transaction twice.

	// If DedupeID is set, the service will check to see if a transaction
	// was previously submitted with the same DedupeID. If one is found,
	// it will NOT submit the transaction again, and will return the status
	// of the previously submitted transaction.
	//
	// Only available on Kin 4.
	DedupeID []byte
}

type payment struct {
	Payment

	createAccountInstructions []solana.Instruction
	createAccountSigner       ed25519.PrivateKey
}

// ReadOnlyPayment represents a kin payment, where
// none of the private keys are known.
type ReadOnlyPayment struct {
	Sender      kin.PublicKey
	Destination kin.PublicKey
	Type        kin.TransactionType
	Quarks      int64

	Invoice *commonpb.Invoice
	Memo    string
}

func parseTransaction(tx solana.Transaction, invoiceList *commonpb.InvoiceList) ([]Creation, []ReadOnlyPayment, error) {
	parsed, err := kin.ParseTransaction(tx, invoiceList)
	if err != nil {
		return nil, nil, err
	}

	creations := make([]Creation, 0)
	payments := make([]ReadOnlyPayment, 0)

	var ilHash []byte
	if invoiceList != nil {
		raw, err := proto.Marshal(invoiceList)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to marshal invoice list")
		}

		ilHash = make([]byte, 28)
		h := sha256.Sum224(raw)
		copy(ilHash, h[:])
	}

	for _, r := range parsed.Regions {
		for _, c := range r.Creations {
			if c.CreateAssoc != nil {
				creations = append(creations, Creation{
					Address: kin.PublicKey(c.CreateAssoc.Address),
					Owner:   kin.PublicKey(c.CreateAssoc.Owner),
				})
			} else if c.Initialize != nil {
				creation := Creation{
					Address: kin.PublicKey(c.Initialize.Account),
				}

				if c.AccountHolder != nil {
					creation.Owner = kin.PublicKey(c.AccountHolder.NewAuthority)
				} else {
					creation.Owner = kin.PublicKey(c.Initialize.Owner)
				}

				creations = append(creations, creation)
			} else {
				return nil, nil, errors.New("invalid solana transaction, create without instruction")
			}
		}

		for i, p := range r.Transfers {
			payment := ReadOnlyPayment{
				Sender:      kin.PublicKey(p.Source),
				Destination: kin.PublicKey(p.Destination),
				Quarks:      int64(p.Amount),
				Type:        kin.TransactionTypeUnknown,
			}

			if r.Memo != nil {
				payment.Type = r.Memo.TransactionType()

				fk := r.Memo.ForeignKey()
				if bytes.Equal(fk[:28], ilHash[:]) && fk[28] == 0 {
					if i >= len(invoiceList.Invoices) {
						return nil, nil, errors.New("invoice list doesn't have sufficient invoices for region")
					}

					payment.Invoice = invoiceList.Invoices[i]
				}
			} else if len(r.MemoData) != 0 {
				payment.Memo = string(r.MemoData)
			}

			payments = append(payments, payment)
		}
	}

	return creations, payments, nil
}

func parseHistoryItem(item *transactionpbv4.HistoryItem) ([]ReadOnlyPayment, TransactionErrors, error) {
	if item.InvoiceList != nil && len(item.InvoiceList.Invoices) != len(item.Payments) {
		return nil, TransactionErrors{}, errors.Errorf(
			"provided invoice count (%d) does not match payment count (%d)",
			len(item.InvoiceList.Invoices),
			len(item.Payments),
		)
	}

	var textMemo string
	var txType kin.TransactionType
	var txErrors TransactionErrors

	switch t := item.RawTransaction.(type) {
	case *transactionpbv4.HistoryItem_SolanaTransaction:
		tx := &solana.Transaction{}
		err := tx.Unmarshal(t.SolanaTransaction.Value)
		if err != nil {
			return nil, TransactionErrors{}, errors.Wrap(err, "failed to unmarshal test transaction")
		}

		if bytes.Equal(tx.Message.Accounts[tx.Message.Instructions[0].ProgramIndex], memo.ProgramKey) {
			m, err := memo.DecompileMemo(tx.Message, 0)
			if err != nil {
				return nil, TransactionErrors{}, errors.Wrap(err, "failed to decompile memo instruction")
			}
			decoded := [32]byte{}
			_, err = base64.StdEncoding.Decode(decoded[:], m.Data)
			if err == nil && kin.IsValidMemoStrict(decoded) {
				txType = kin.Memo(decoded).TransactionType()
			} else {
				textMemo = string(m.Data)
			}
		}
		txErrors = errorsFromSolanaTx(tx, item.TransactionError)
	case *transactionpbv4.HistoryItem_StellarTransaction:
		var envelope xdr.TransactionEnvelope
		if err := envelope.UnmarshalBinary(t.StellarTransaction.EnvelopeXdr); err != nil {
			return nil, TransactionErrors{}, errors.Wrap(err, "failed to unmarshal xdr")
		}

		kinMemo, ok := kin.MemoFromXDR(envelope.Tx.Memo, true)
		if ok {
			txType = kinMemo.TransactionType()
		} else if envelope.Tx.Memo.Text != nil {
			textMemo = *envelope.Tx.Memo.Text
		}
		txErrors = errorsFromStellarTx(envelope, item.TransactionError)
	}

	payments := make([]ReadOnlyPayment, len(item.Payments))
	for i, payment := range item.Payments {
		p := ReadOnlyPayment{
			Sender:      payment.Source.Value,
			Destination: payment.Destination.Value,
			Type:        txType,
			Quarks:      payment.Amount,
		}
		if item.InvoiceList != nil {
			p.Invoice = item.InvoiceList.Invoices[i]
		} else if textMemo != "" {
			p.Memo = textMemo
		}
		payments[i] = p
	}

	return payments, txErrors, nil

}

// TransactionData contains high level metadata and payments
// contained in a transaction.
type TransactionData struct {
	TxID     []byte
	TxState  TransactionState
	Payments []ReadOnlyPayment
	Errors   TransactionErrors
}

type TransactionState int

const (
	TransactionStateUnknown TransactionState = iota
	TransactionStateSuccess
	TransactionStateFailed
	TransactionStatePending
)

func txStateFromProto(state transactionpbv4.GetTransactionResponse_State) TransactionState {
	switch state {
	case transactionpbv4.GetTransactionResponse_SUCCESS:
		return TransactionStateSuccess
	case transactionpbv4.GetTransactionResponse_FAILED:
		return TransactionStateFailed
	case transactionpbv4.GetTransactionResponse_PENDING:
		return TransactionStatePending
	default:
		return TransactionStateUnknown
	}
}

// EarnBatch is a batch of Earn payments coming from a single
// sender/source.
type EarnBatch struct {
	Sender kin.PrivateKey

	Memo string

	Earns []Earn

	// DedupeID is a unique identifier used by the service to help prevent the
	// accidental submission of the same intended transaction twice.

	// If DedupeID is set, the service will check to see if a transaction
	// was previously submitted with the same DedupeID. If one is found,
	// it will NOT submit the transaction again, and will return the status
	// of the previously submitted transaction.
	//
	// Only available on Kin 4.
	DedupeID []byte
}

// Earn represents a earn payment in an earn batch.
type Earn struct {
	Destination kin.PublicKey
	Quarks      int64
	Invoice     *commonpb.Invoice
}

// EarnBatchResult contains the result of an EarnBatch transaction.
type EarnBatchResult struct {
	TxID []byte

	// If TxError is defined, the transaction failed.
	TxError error

	// EarnErrors contains any available earn-specific error information.
	//
	// EarnErrors may or may not be set if TxError is set.
	EarnErrors []EarnError
}

type EarnError struct {
	EarnIndex int
	Error     error
}

// AccountResolution is used to indicate which type of account resolution should be used if a transaction on Kin 4 fails
// due to an account being unavailable.
//
type AccountResolution int

const (
	// AccountResolutionExact indicates no account resolution will be used.
	AccountResolutionExact AccountResolution = iota

	// AccountResolutionPreferred indicates that in the case an account is not found, the client will reattempt
	// submission with any resolved token accounts.
	//
	// When used for a sender key in a payment or earn request, if Agora is able to resolve the original sender public
	// key to a set of token accounts, the original sender will be used as the owner in the Solana transfer
	// instruction and the first resolved token account will be used as the sender.
	//
	// When used for a destination key in a payment or earn request, if Agora is able to resolve the destination key to
	// a set of token accounts, the first resolved token account will be used as the destination in the Solana transfer
	// instruction.
	AccountResolutionPreferred
)

// EventsResult contains the result received from an account event stream. Either Events or Err will be set.
type EventsResult struct {
	Events []*accountpbv4.Event
	Err    error
}
