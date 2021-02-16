package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/solana/memo"
	"github.com/kinecosystem/agora-common/solana/token"
	"github.com/kinecosystem/agora-common/webhook/events"
	"github.com/kinecosystem/agora-common/webhook/signtransaction"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"

	"github.com/kinecosystem/kin-go/client/testutil"
)

func TestEventsHandler(t *testing.T) {
	data := []events.Event{
		{
			TransactionEvent: &events.TransactionEvent{
				KinVersion: 3,
				TxHash:     []byte("hash"),
				TxID:       []byte("hash"),
				InvoiceList: &commonpb.InvoiceList{
					Invoices: []*commonpb.Invoice{
						{
							Items: []*commonpb.Invoice_LineItem{
								{
									Title: "hello",
								},
							},
						},
					},
				},
				StellarEvent: &events.StellarEvent{
					EnvelopeXDR: []byte("envelope"),
					ResultXDR:   []byte("result"),
				},
			},
		},
		{
			TransactionEvent: &events.TransactionEvent{
				KinVersion: 4,
				TxHash:     []byte("sig"),
				TxID:       []byte("sig"),
				InvoiceList: &commonpb.InvoiceList{
					Invoices: []*commonpb.Invoice{
						{
							Items: []*commonpb.Invoice_LineItem{
								{
									Title: "hello",
								},
							},
						},
					},
				},
				SolanaEvent: &events.SolanaEvent{
					Transaction:         []byte("transaction"),
					TransactionError:    "error",
					TransactionErrorRaw: []byte("error"),
				},
			},
		},
	}

	called := false
	f := func(events []events.Event) error {
		called = true
		assert.Equal(t, data, events)
		return nil
	}

	body, err := json.Marshal(data)
	require.NoError(t, err)

	secret := "secret"
	b := bytes.NewBuffer(body)
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write(b.Bytes())
	sig := h.Sum(nil)

	req, err := http.NewRequest(http.MethodPost, "/events", b)
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))

	rr := httptest.NewRecorder()
	handler := EventsHandler(secret, f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, called)

	// if no webhook secret was provided, don't validate
	req, err = http.NewRequest(http.MethodPost, "/events", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString([]byte("fake sig")))

	rr = httptest.NewRecorder()
	handler = EventsHandler("", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, called)

	f = func([]events.Event) error {
		return errors.New("server error")
	}

	b = bytes.NewBuffer(body)

	req, err = http.NewRequest(http.MethodPost, "/events", b)
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))

	rr = httptest.NewRecorder()
	handler = EventsHandler(secret, f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestEventsHandler_Invalid(t *testing.T) {
	f := func(events []events.Event) error {
		t.Fail()
		return nil
	}

	var invalidMethodRequest []*http.Request
	invalidMethods := []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodPatch,
		http.MethodPut,
		http.MethodTrace,
	}
	for _, m := range invalidMethods {
		req, err := http.NewRequest(m, "/events", nil)
		require.NoError(t, err)
		invalidMethodRequest = append(invalidMethodRequest, req)
	}
	for _, r := range invalidMethodRequest {
		rr := httptest.NewRecorder()
		handler := EventsHandler("secret", f)
		handler.ServeHTTP(rr, r)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	}

	secret := "secret"
	b := bytes.NewBuffer([]byte("{"))
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write(b.Bytes())
	sig := h.Sum(nil)

	// Generic bad request
	req, err := http.NewRequest(http.MethodPost, "/events", b)
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))

	rr := httptest.NewRecorder()
	handler := EventsHandler("secret", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Invalid sig
	req, err = http.NewRequest(http.MethodPost, "/events", b)
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString([]byte("fake sig")))

	rr = httptest.NewRecorder()
	handler = EventsHandler("secret", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// No sig
	req, err = http.NewRequest(http.MethodPost, "/events", b)
	require.NoError(t, err)

	rr = httptest.NewRecorder()
	handler = EventsHandler("secret", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestSignTransactionHandler(t *testing.T) {
	whitelist, err := kin.NewPrivateKey()
	require.NoError(t, err)

	called := false
	f := func(req SignTransactionRequest, resp *SignTransactionResponse) error {
		assert.NotNil(t, req.SolanaTransaction)
		assert.Len(t, req.Payments, 10)

		var memoCount, invoiceCount int
		for _, p := range req.Payments {
			assert.NotEmpty(t, p.Sender)
			assert.NotEmpty(t, p.Destination)
			assert.NotZero(t, p.Quarks)

			if p.Memo != "" {
				assert.Len(t, req.SolanaTransaction.Message.Instructions, 11)
				assert.Equal(t, kin.TransactionTypeUnknown, p.Type)
				memoCount++
			} else if p.Invoice != nil {
				assert.Len(t, req.SolanaTransaction.Message.Instructions, 11)
				assert.Equal(t, kin.TransactionTypeSpend, p.Type)
				invoiceCount++
			} else {
				assert.Len(t, req.SolanaTransaction.Message.Instructions, 10)
				assert.Equal(t, kin.TransactionTypeUnknown, p.Type)
			}
		}

		if memoCount > 0 {
			assert.Equal(t, 10, memoCount)
			assert.Zero(t, invoiceCount)
		} else if invoiceCount > 0 {
			assert.Zero(t, memoCount)
			assert.Equal(t, 10, invoiceCount)
		} else {
			assert.Zero(t, memoCount)
			assert.Zero(t, invoiceCount)
		}

		called = true
		return resp.Sign(whitelist) // no-op for kin 4
	}

	signRequests := []signtransaction.Request{
		genRequest(t, false, false, 4),
		genRequest(t, false, true, 4),
		genRequest(t, true, false, 4),
	}
	for _, data := range signRequests {
		body, err := json.Marshal(data)
		require.NoError(t, err)

		secret := "secret"
		b := bytes.NewBuffer(body)
		h := hmac.New(sha256.New, []byte(secret))
		_, _ = h.Write(b.Bytes())
		sig := h.Sum(nil)

		req, err := http.NewRequest(http.MethodPost, "/sign_transaction", b)
		require.NoError(t, err)
		req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))

		rr := httptest.NewRecorder()
		handler := SignTransactionHandler(EnvironmentTest, secret, f)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, called)
		called = false

		var resp signtransaction.SuccessResponse
		assert.NoError(t, json.NewDecoder(rr.Result().Body).Decode(&resp))
		assert.Nil(t, resp.EnvelopeXDR)
	}

	// if no webhook secret was provided, don't validate
	signRequest := genRequest(t, false, false, 4)
	body, err := json.Marshal(signRequest)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "/sign_transaction", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString([]byte("fake sig")))

	rr := httptest.NewRecorder()
	handler := SignTransactionHandler(EnvironmentTest, "", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, called)
}

func TestSignTransactionHandler_Rejected(t *testing.T) {
	called := false
	f := func(req SignTransactionRequest, resp *SignTransactionResponse) error {
		called = true
		resp.Reject()
		return nil
	}

	signRequests := []signtransaction.Request{
		genRequest(t, false, false, 4),
	}
	for _, data := range signRequests {
		body, err := json.Marshal(data)
		require.NoError(t, err)

		secret := "secret"
		b := bytes.NewBuffer(body)
		h := hmac.New(sha256.New, []byte(secret))
		_, _ = h.Write(b.Bytes())
		sig := h.Sum(nil)

		req, err := http.NewRequest(http.MethodPost, "/sign_transaction", b)
		require.NoError(t, err)
		req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))

		rr := httptest.NewRecorder()
		handler := SignTransactionHandler(EnvironmentTest, secret, f)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.True(t, called)
		called = false

		var resp signtransaction.ForbiddenResponse
		assert.NoError(t, json.NewDecoder(rr.Result().Body).Decode(&resp))
		assert.Equal(t, resp.Message, "rejected")
		assert.Empty(t, resp.InvoiceErrors)
	}
}

func TestSignTransactionHandler_InvoiceErrors(t *testing.T) {
	called := false
	f := func(req SignTransactionRequest, resp *SignTransactionResponse) error {
		called = true

		resp.MarkAlreadyPaid(0)
		resp.MarkWrongDestination(3)
		resp.MarkSKUNotFound(5)

		return nil
	}

	signRequests := []signtransaction.Request{
		genRequest(t, false, false, 4),
	}
	for _, data := range signRequests {
		body, err := json.Marshal(data)
		require.NoError(t, err)

		secret := "secret"
		b := bytes.NewBuffer(body)
		h := hmac.New(sha256.New, []byte(secret))
		_, _ = h.Write(b.Bytes())
		sig := h.Sum(nil)

		req, err := http.NewRequest(http.MethodPost, "/sign_transaction", b)
		require.NoError(t, err)
		req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))

		rr := httptest.NewRecorder()
		handler := SignTransactionHandler(EnvironmentTest, secret, f)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.True(t, called)
		called = false

		var resp signtransaction.ForbiddenResponse
		assert.NoError(t, json.NewDecoder(rr.Result().Body).Decode(&resp))
		assert.Equal(t, resp.Message, "rejected")
		assert.Len(t, resp.InvoiceErrors, 3)

		assert.EqualValues(t, resp.InvoiceErrors[0].OperationIndex, 0)
		assert.EqualValues(t, resp.InvoiceErrors[0].Reason, signtransaction.AlreadyPaid)
		assert.EqualValues(t, resp.InvoiceErrors[1].OperationIndex, 3)
		assert.EqualValues(t, resp.InvoiceErrors[1].Reason, signtransaction.WrongDestination)
		assert.EqualValues(t, resp.InvoiceErrors[2].OperationIndex, 5)
		assert.EqualValues(t, resp.InvoiceErrors[2].Reason, signtransaction.SKUNotFound)
	}
}

func TestSignTransactionHandler_Invalid(t *testing.T) {
	f := func(req SignTransactionRequest, resp *SignTransactionResponse) error {
		t.Fail()
		return nil
	}

	var invalidMethodRequest []*http.Request
	invalidMethods := []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodPatch,
		http.MethodPut,
		http.MethodTrace,
	}
	for _, m := range invalidMethods {
		req, err := http.NewRequest(m, "/sign_transaction", nil)
		require.NoError(t, err)
		invalidMethodRequest = append(invalidMethodRequest, req)
	}
	for _, r := range invalidMethodRequest {
		rr := httptest.NewRecorder()
		handler := SignTransactionHandler(EnvironmentTest, "secret", f)
		handler.ServeHTTP(rr, r)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	}

	secret := "secret"
	b := bytes.NewBuffer([]byte("{"))
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write(b.Bytes())
	sig := h.Sum(nil)

	// Generic bad request
	req, err := http.NewRequest(http.MethodPost, "/sign_transaction", b)
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))

	rr := httptest.NewRecorder()
	handler := SignTransactionHandler(EnvironmentTest, "secret", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Invalid sig
	req, err = http.NewRequest(http.MethodPost, "/sign_transaction", b)
	require.NoError(t, err)
	req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString([]byte("fake sig")))

	rr = httptest.NewRecorder()
	handler = SignTransactionHandler(EnvironmentTest, "secret", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// No sig
	req, err = http.NewRequest(http.MethodPost, "/sign_transaction", b)
	require.NoError(t, err)

	rr = httptest.NewRecorder()
	handler = SignTransactionHandler(EnvironmentTest, "secret", f)
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	makeReq := func(r signtransaction.Request) *http.Request {
		body, err := json.Marshal(&r)
		require.NoError(t, err)

		b := bytes.NewBuffer(body)
		h := hmac.New(sha256.New, []byte(secret))
		_, _ = h.Write(b.Bytes())
		sig := h.Sum(nil)

		req, err = http.NewRequest(http.MethodPost, "/sign_transaction", b)
		require.NoError(t, err)
		req.Header.Add(AgoraHMACHeader, base64.StdEncoding.EncodeToString(sig[:]))
		return req
	}

	// Invalid version
	signReq := genRequest(t, false, false, 1)
	rr = httptest.NewRecorder()
	handler = SignTransactionHandler(EnvironmentTest, "", f)
	handler.ServeHTTP(rr, makeReq(signReq))

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Generate a request with mis-matched invoice counts
	signReq = genRequest(t, true, false, 4)
	invoiceList := &commonpb.InvoiceList{}
	assert.NoError(t, proto.Unmarshal(signReq.InvoiceList, invoiceList))
	invoiceList.Invoices = invoiceList.Invoices[1:]
	ilBytes, err := proto.Marshal(invoiceList)
	require.NoError(t, err)
	signReq.InvoiceList = ilBytes

	rr = httptest.NewRecorder()
	handler = SignTransactionHandler(EnvironmentTest, "secret", f)
	handler.ServeHTTP(rr, makeReq(signReq))

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Generate a request with malformed XDR
	signReq = genRequest(t, false, false, 4)
	signReq.SolanaTransaction = []byte("somebytes")

	rr = httptest.NewRecorder()
	handler = SignTransactionHandler(EnvironmentTest, "secret", f)
	handler.ServeHTTP(rr, makeReq(signReq))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Generate a request with a malformed invoice list
	signReq = genRequest(t, true, false, 4)
	signReq.InvoiceList = signReq.InvoiceList[1:]
	rr = httptest.NewRecorder()
	handler = SignTransactionHandler(EnvironmentTest, "secret", f)
	handler.ServeHTTP(rr, makeReq(signReq))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Generate kin 4 with no solana transaction
	signReq = genRequest(t, false, false, 4)
	signReq.SolanaTransaction = nil

	rr = httptest.NewRecorder()
	handler = SignTransactionHandler(EnvironmentTest, "secret", f)
	handler.ServeHTTP(rr, makeReq(signReq))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func genRequest(t *testing.T, useInvoice, useMemo bool, version int) signtransaction.Request {
	accounts := make([]ed25519.PrivateKey, 10)
	for i := 0; i < 10; i++ {
		accounts[i] = testutil.GenerateSolanaKeypair(t)
	}

	var transfers []solana.Instruction
	for i := 0; i < 10; i++ {
		transfers = append(transfers, token.Transfer(
			accounts[0].Public().(ed25519.PublicKey),
			accounts[i].Public().(ed25519.PublicKey),
			accounts[0].Public().(ed25519.PublicKey),
			1))
	}

	req := signtransaction.Request{
		KinVersion: 4,
	}

	var instructions []solana.Instruction
	if useMemo {
		m := "1-test"
		instructions = append(instructions, memo.Instruction(m))
	} else if useInvoice {
		invoiceList := &commonpb.InvoiceList{}
		for i := 0; i < 10; i++ {
			invoiceList.Invoices = append(invoiceList.Invoices, &commonpb.Invoice{
				Items: []*commonpb.Invoice_LineItem{
					{
						Title:  "test",
						Amount: int64(i),
					},
				},
			})
		}

		ilBytes, err := proto.Marshal(invoiceList)
		require.NoError(t, err)
		req.InvoiceList = ilBytes

		b, err := proto.Marshal(invoiceList)
		require.NoError(t, err)
		h := sha256.Sum224(b)

		m, err := kin.NewMemo(1, kin.TransactionTypeSpend, 1, h[:])
		require.NoError(t, err)

		instructions = append(instructions, memo.Instruction(base64.StdEncoding.EncodeToString(m[:])))
	}
	instructions = append(instructions, transfers...)

	var err error
	req.SolanaTransaction = solana.NewTransaction(accounts[0].Public().(ed25519.PublicKey), instructions...).Marshal()
	req.KinVersion = version
	require.NoError(t, err)
	return req
}
