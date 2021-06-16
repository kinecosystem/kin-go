package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/webhook/createaccount"
	"github.com/kinecosystem/agora-common/webhook/events"
	"github.com/kinecosystem/agora-common/webhook/signtransaction"
	"github.com/pkg/errors"

	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"
)

const (
	AgoraHMACHeader      = "X-Agora-HMAC-SHA256"
	AppUserIDHeader      = "X-App-User-ID"
	AppUserPasskeyHeader = "X-App-User-Passkey"
)

// EventsFunc is a callback function for the Events webhook.
//
// If an error is returned, an InternalServer error is returned
// to Agora. Agora will retry a limited amount of times when an
// InternalServerError is returned.
type EventsFunc func([]events.Event) error

// EventsHandler returns an http.HandlerFunc that decodes and verifies
// an Events webhook call, before forwarding it to the specified EventsFunc.
func EventsHandler(secret string, f EventsFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to ready body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(secret) > 0 {
			if err := verifySignature(r.Header, body, []byte(secret)); err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
		}

		var events []events.Event
		if err := json.Unmarshal(body, &events); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}

		if err := f(events); err != nil {
			http.Error(w, "", http.StatusInternalServerError)
		}
	}
}

type CreateAccountFunc func(CreateAccountRequest, *CreateAccountResponse) error

type CreateAccountRequest struct {
	Creation    Creation
	Transaction *solana.Transaction
}

type CreateAccountResponse struct {
	rejected bool
	tx       *solana.Transaction
}

// Sign signs the underlying transaction with the specified private key.
func (c *CreateAccountResponse) Sign(priv kin.PrivateKey) (err error) {
	if len(c.tx.Signatures) > len(c.tx.Message.Accounts) {
		return errors.New("invalid transaction: more signers than accounts")
	}

	// Check to see if our public key corresponds to a signer
	if bytes.Equal(priv.Public(), c.tx.Message.Accounts[0]) {
		return c.tx.Sign(ed25519.PrivateKey(priv))
	}

	return nil
}

func (c *CreateAccountResponse) Reject() {
	c.rejected = true
}

func CreateAccountHandler(secret string, f CreateAccountFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to ready body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(secret) > 0 {
			if err := verifySignature(r.Header, body, []byte(secret)); err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
		}

		var createRequest createaccount.Request
		if err = json.Unmarshal(body, &createRequest); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}

		// If no kin version is set, default to Kin 4
		if createRequest.KinVersion == 0 {
			createRequest.KinVersion = 4
		}

		if createRequest.KinVersion != 4 {
			http.Error(w, fmt.Sprintf("unsupported kin version %d", createRequest.KinVersion), http.StatusBadRequest)
			return
		}

		var tx solana.Transaction
		if err := tx.Unmarshal(createRequest.SolanaTransaction); err != nil {
			http.Error(w, "invalid solana tx", http.StatusBadRequest)
			return
		}

		req := CreateAccountRequest{
			Transaction: &tx,
		}
		resp := CreateAccountResponse{
			tx: &tx,
		}

		creations, payments, err := parseTransaction(*req.Transaction, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(payments) != 0 {
			http.Error(w, "unexpected payments present", http.StatusBadRequest)
			return
		}
		if len(creations) != 1 {
			http.Error(w, fmt.Sprintf("expected exactly 1 creation, got %d", len(creations)), http.StatusBadRequest)
			return
		}

		req.Creation = creations[0]

		if err := f(req, &resp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)

		if resp.rejected {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		successResp := createaccount.SuccessResponse{}
		if resp.tx.Signatures[0] != (solana.Signature{}) {
			successResp.Signature = resp.tx.Signature()
		}
		if err := encoder.Encode(&successResp); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}
}

// SignTransactionFunc is a callback function for the SignTransaction webhook.
//
// If an error is returned, an InternalServer error is returned
// to Agora, and then back to the client.
//
// To reject transactions based on specific invoice failures, use the
// Mark functions on the SignTransactionResponse.
//
// To reject transactions without reason, use the Reject function on the
// SignTransactionResponse.
//
// Authorized transactions should be signed with the Sign function.
type SignTransactionFunc func(SignTransactionRequest, *SignTransactionResponse) error

// SignTransactionRequest contains the transaction and payment data that
// is requesting to be signed/approved.
type SignTransactionRequest struct {
	// The Kin Version provided by the client (optional)
	// The UserID provided by the client (optional).
	UserID string
	// The UserPassKey provided by the client (optional).
	UserPasskey string

	// Account creations required for payments.
	Creations []Creation

	// Payments is a set of payments that a client wishes to be signed.
	Payments []ReadOnlyPayment

	// SolanaTransaction is included _only_ for further validation by SDK consumers,
	// which is optional.
	//
	// It will only be set on Solana-based transactions, and is _not_ a stable API.
	SolanaTransaction *solana.Transaction
}

// TxID returns the ID of the transaction in this request.
//
// It will either be a 32-byte Stellar transaction hash or a 64-byte Solana transaction signature.
func (s *SignTransactionRequest) TxID() ([]byte, error) {
	if s.SolanaTransaction != nil {
		return s.SolanaTransaction.Signature(), nil
	}
	return nil, errors.New("this request has no transaction")
}

// SignTransactionResponse contains the response information related to a request.
//
// It is the primary mechanism in which a SignTransactionRequest can be signed or
// rejected.
type SignTransactionResponse struct {
	rejected bool
	errors   []signtransaction.InvoiceError
	tx       *solana.Transaction
}

// Sign signs the underlying transaction with the specified private key.
func (r *SignTransactionResponse) Sign(priv kin.PrivateKey) (err error) {
	if len(r.tx.Signatures) > len(r.tx.Message.Accounts) {
		return errors.New("invalid transaction: more signers than accounts")
	}

	// Check to see if our public key corresponds to a signer
	if bytes.Equal(priv.Public(), r.tx.Message.Accounts[0]) {
		return r.tx.Sign(ed25519.PrivateKey(priv))
	}

	return nil
}

// Reject indicates the transaction should be rejected, without reason.
func (r *SignTransactionResponse) Reject() {
	r.rejected = true
}

// IsRejected returns whether or not the transaction should be rejected,
// with or without reason.
func (r *SignTransactionResponse) IsRejected() bool {
	return r.rejected
}

// MarkAlreadyPaid marks the Payment at index idx as paid.
//
// This causes the entire transaction to be rejected.
func (r *SignTransactionResponse) MarkAlreadyPaid(idx int) {
	r.rejected = true
	r.errors = append(r.errors, signtransaction.InvoiceError{
		OperationIndex: uint32(idx),
		Reason:         signtransaction.AlreadyPaid,
	})
}

// MarkWrongDestination marks the Payment at index idx as having the
// wrong destination.
//
// This causes the entire transaction to be rejected.
func (r *SignTransactionResponse) MarkWrongDestination(idx int) {
	r.rejected = true
	r.errors = append(r.errors, signtransaction.InvoiceError{
		OperationIndex: uint32(idx),
		Reason:         signtransaction.WrongDestination,
	})
}

// MarkSKUNotFound marks the Payment at index idx as having the
// an unknown SKU value.
//
// This causes the entire transaction to be rejected.
func (r *SignTransactionResponse) MarkSKUNotFound(idx int) {
	r.rejected = true
	r.errors = append(r.errors, signtransaction.InvoiceError{
		OperationIndex: uint32(idx),
		Reason:         signtransaction.SKUNotFound,
	})
}

// SignTransactionHandler returns an http.HandlerFunc that decodes and verifies
// a signtransaction webhook call, before forwarding it to the specified SignTransactionFunc.
func SignTransactionHandler(secret string, f SignTransactionFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			// todo(consistency): double check error code response
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to ready body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(secret) > 0 {
			if err := verifySignature(r.Header, body, []byte(secret)); err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
		}

		var signRequest signtransaction.Request
		if err = json.Unmarshal(body, &signRequest); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}

		// If no kin version is set, default to Kin 4
		if signRequest.KinVersion == 0 {
			signRequest.KinVersion = 4
		}

		if signRequest.KinVersion != 4 {
			http.Error(w, fmt.Sprintf("unsupported kin version %d", signRequest.KinVersion), http.StatusBadRequest)
			return
		}

		var invoiceList *commonpb.InvoiceList
		if len(signRequest.InvoiceList) > 0 {
			invoiceList = &commonpb.InvoiceList{}
			if err = proto.Unmarshal(signRequest.InvoiceList, invoiceList); err != nil {
				http.Error(w, "invalid invoice list", http.StatusBadRequest)
				return
			}
		}

		req := SignTransactionRequest{
			UserID:      r.Header.Get(AppUserIDHeader),
			UserPasskey: r.Header.Get(AppUserPasskeyHeader),
		}

		var tx solana.Transaction
		if err = tx.Unmarshal(signRequest.SolanaTransaction); err != nil {
			http.Error(w, "invalid solana tx", http.StatusBadRequest)
			return
		}

		req.SolanaTransaction = &tx
		req.Creations, req.Payments, err = parseTransaction(tx, invoiceList)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := &SignTransactionResponse{
			tx: req.SolanaTransaction,
		}

		if err := f(req, resp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)

		if resp.IsRejected() {
			w.WriteHeader(http.StatusForbidden)

			rejectResp := signtransaction.ForbiddenResponse{
				Message:       "rejected",
				InvoiceErrors: resp.errors,
			}
			if err := encoder.Encode(&rejectResp); err != nil {
				http.Error(w, "failed to encode response", http.StatusInternalServerError)
			}

			return
		}

		successResp := signtransaction.SuccessResponse{}
		if resp.tx.Signatures[0] != (solana.Signature{}) {
			successResp.Signature = resp.tx.Signature()
		}
		if err = encoder.Encode(&successResp); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}
}

func verifySignature(header http.Header, body, secret []byte) error {
	encodedSig := header.Get(AgoraHMACHeader)
	if encodedSig == "" {
		return errors.New("missing signature")
	}

	sig, err := base64.StdEncoding.DecodeString(encodedSig)
	if err != nil {
		return errors.Wrap(err, "invalid signature")
	}

	h := hmac.New(sha256.New, []byte(secret))
	if _, err := h.Write(body); err != nil {
		return err
	}

	expected := h.Sum(nil)
	if !hmac.Equal(expected, sig) {
		// todo: well known error type?
		return errors.New("hmac signature mismatch")
	}

	return nil
}
