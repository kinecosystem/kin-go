package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/solana/memo"
	"github.com/kinecosystem/agora-common/solana/token"
	"github.com/kinecosystem/kin-go/client/testutil"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kinecosystem/agora-api/genproto/account/v4"
	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"
	commonpbv4 "github.com/kinecosystem/agora-api/genproto/common/v4"
	transactionpbv4 "github.com/kinecosystem/agora-api/genproto/transaction/v4"
)

func TestClient_GetTransaction(t *testing.T) {
	// currently this proxies directly to internal, which has tests.
	// if this changes, we should add more tests here.
}

func TestClient_AppIndexNotSet(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	c, err := New(
		EnvironmentTest,
		WithGRPC(env.conn),
		WithMaxRetries(3),
		WithMinDelay(time.Millisecond),
		WithMaxDelay(time.Millisecond),
	)
	require.NoError(t, err)

	setServiceConfigResp(t, env.v4Server, true)

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)
	require.NoError(t, env.client.CreateAccount(context.Background(), sender))
	dest, err := kin.NewPrivateKey()
	require.NoError(t, err)
	require.NoError(t, env.client.CreateAccount(context.Background(), dest))

	payments := []Payment{
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
		},
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
			Memo:        "1-test",
		},
	}

	for _, p := range payments {
		_, err = c.SubmitPayment(context.Background(), p)
		assert.NoError(t, err)
	}

	invoicePayment := Payment{
		Sender:      sender,
		Destination: dest.Public(),
		Type:        kin.TransactionTypeSpend,
		Quarks:      11,
		Invoice: &commonpb.Invoice{
			Items: []*commonpb.Invoice_LineItem{
				{
					Title:  "test",
					Amount: 11,
				},
			},
		},
	}

	_, err = c.SubmitPayment(context.Background(), invoicePayment)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "without an app index"))
}

func TestClient_AccountManagement(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	mint, _, _ := setServiceConfigResp(t, env.v4Server, true)

	priv, err := kin.NewPrivateKey()
	require.NoError(t, err)

	tokenAcc, err := token.GetAssociatedAccount(ed25519.PublicKey(priv.Public()), mint)
	require.NoError(t, err)

	balance, err := env.client.GetBalance(context.Background(), kin.PublicKey(tokenAcc))
	assert.Equal(t, ErrAccountDoesNotExist, err)
	assert.Zero(t, balance)

	err = env.client.CreateAccount(context.Background(), priv)
	assert.NoError(t, err)

	err = env.client.CreateAccount(context.Background(), priv)
	assert.Equal(t, ErrAccountExists, err)

	balance, err = env.client.GetBalance(context.Background(), kin.PublicKey(tokenAcc))
	assert.NoError(t, err)
	assert.EqualValues(t, 10, balance)

	// Test resolution options
	balance, err = env.client.GetBalance(context.Background(), priv.Public(), WithAccountResolution(AccountResolutionExact))
	assert.Equal(t, ErrAccountDoesNotExist, err)
	assert.Zero(t, balance)

	balance, err = env.client.GetBalance(context.Background(), priv.Public())
	require.NoError(t, err)
	assert.EqualValues(t, 10, balance)

	var createTx solana.Transaction
	assert.NoError(t, createTx.Unmarshal(env.v4Server.Creates[0].Transaction.Value))
	assert.Equal(t, 3, len(createTx.Message.Instructions))

	memoInstruction, err := memo.DecompileMemo(createTx.Message, 0)
	assert.NoError(t, err)

	m, err := kin.MemoFromBase64String(string(memoInstruction.Data), false)
	assert.NoError(t, err)
	assert.EqualValues(t, 1, m.AppIndex())
	assert.Equal(t, kin.TransactionTypeNone, m.TransactionType())
}

func TestClient_CreateWithoutAttribution(t *testing.T) {
	env, cleanup := setup(t, WithAppIndex(0))
	defer cleanup()

	mint, _, _ := setServiceConfigResp(t, env.v4Server, true)

	priv, err := kin.NewPrivateKey()
	require.NoError(t, err)

	tokenAcc, err := token.GetAssociatedAccount(ed25519.PublicKey(priv.Public()), mint)
	require.NoError(t, err)

	balance, err := env.client.GetBalance(context.Background(), kin.PublicKey(tokenAcc))
	assert.Equal(t, ErrAccountDoesNotExist, err)
	assert.Zero(t, balance)

	err = env.client.CreateAccount(context.Background(), priv)
	assert.NoError(t, err)

	var createTx solana.Transaction
	assert.NoError(t, createTx.Unmarshal(env.v4Server.Creates[0].Transaction.Value))
	assert.Equal(t, 2, len(createTx.Message.Instructions))

	_, err = token.DecompileCreateAssociatedAccount(createTx.Message, 0)
	assert.NoError(t, err)
	_, err = token.DecompileSetAuthority(createTx.Message, 1)
	assert.NoError(t, err)
}

func TestClient_MergeAccount(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	priv, err := kin.NewPrivateKey()
	require.NoError(t, err)

	otherSubsidizer := testutil.GenerateSolanaKeys(t, 1)[0]

	_, _, subsidizer := setServiceConfigResp(t, env.v4Server, true)
	tokenAccounts := testutil.GenerateSolanaKeys(t, 4)
	closeAuthorities := make([]ed25519.PublicKey, len(tokenAccounts))
	closeAuthorities[0] = subsidizer
	closeAuthorities[1] = subsidizer
	closeAuthorities[2] = otherSubsidizer
	closeAuthorities[3] = ed25519.PublicKey(priv.Public())

	// Manually register a bunch of token accounts that we expect to be merged.
	env.v4Server.Mux.Lock()

	ownerKey := priv.Public().Base58()

	for i := 0; i < len(tokenAccounts); i++ {
		env.v4Server.Accounts[base58.Encode(tokenAccounts[i])] = &account.AccountInfo{
			AccountId: &commonpbv4.SolanaAccountId{
				Value: tokenAccounts[i],
			},
			Balance: int64(i) * 10,
			Owner: &commonpbv4.SolanaAccountId{
				Value: priv.Public(),
			},
			CloseAuthority: &commonpbv4.SolanaAccountId{
				Value: closeAuthorities[i],
			},
		}
		env.v4Server.TokenAccounts[ownerKey] = append(env.v4Server.TokenAccounts[ownerKey], &commonpbv4.SolanaAccountId{
			Value: tokenAccounts[i],
		})
	}
	env.v4Server.Mux.Unlock()

	// Ensure the initial resolve returns the correct accounts
	accounts, err := env.internal.ResolveTokenAccounts(context.Background(), priv.Public(), true)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(accounts))
	env.v4Server.Mux.Lock()
	for _, a := range accounts {
		var found bool
		for i, e := range tokenAccounts {
			if bytes.Equal(a.AccountId.Value, e) {
				assert.EqualValues(t, i*10, a.Balance)
				found = true
				break
			}
		}
		assert.True(t, found)
	}
	assert.Equal(t, 0, len(env.v4Server.Submits))
	env.v4Server.Mux.Unlock()

	txID, err := env.client.MergeTokenAccounts(context.Background(), priv, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(env.v4Server.Submits))

	var tx solana.Transaction
	assert.NoError(t, tx.Unmarshal(env.v4Server.Submits[0].Transaction.Value))
	assert.Equal(t, tx.Signature(), txID)
	parsed, err := kin.ParseTransaction(tx, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsed.Regions))
	assert.Equal(t, 0, len(parsed.Regions[0].Creations))
	assert.Equal(t, 3, len(parsed.Regions[0].Transfers))
	assert.Equal(t, 2, len(parsed.Regions[0].Closures))

	for _, xfer := range parsed.Regions[0].Transfers {
		assert.EqualValues(t, priv.Public(), xfer.Owner)
		assert.EqualValues(t, accounts[0].AccountId.Value, xfer.Destination)

		for i, tc := range tokenAccounts {
			if bytes.Equal(tc, xfer.Source) {
				assert.EqualValues(t, i*10, xfer.Amount)
			}
		}
	}

	for _, closure := range parsed.Regions[0].Closures {
		assert.False(t, bytes.Equal(closure.Account, accounts[0].AccountId.Value))

		for i, tc := range tokenAccounts {
			if bytes.Equal(tc, closure.Account) {
				assert.EqualValues(t, closeAuthorities[i], closure.Destination)
				assert.EqualValues(t, closeAuthorities[i], closure.Owner)
			}
		}
	}
}

func TestClient_MergeAccount_CustomSubsidizer(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	priv, err := kin.NewPrivateKey()
	require.NoError(t, err)

	otherSubsidizerPriv := testutil.GenerateSolanaKeypair(t)
	otherSubsidizer := otherSubsidizerPriv.Public().(ed25519.PublicKey)

	_, _, subsidizer := setServiceConfigResp(t, env.v4Server, true)
	tokenAccounts := testutil.GenerateSolanaKeys(t, 4)
	closeAuthorities := make([]ed25519.PublicKey, len(tokenAccounts))
	closeAuthorities[0] = subsidizer
	closeAuthorities[1] = subsidizer
	closeAuthorities[2] = otherSubsidizer
	closeAuthorities[3] = ed25519.PublicKey(priv.Public())

	// Manually register a bunch of token accounts that we expect to be merged.
	env.v4Server.Mux.Lock()

	ownerKey := priv.Public().Base58()

	for i := 0; i < len(tokenAccounts); i++ {
		env.v4Server.Accounts[base58.Encode(tokenAccounts[i])] = &account.AccountInfo{
			AccountId: &commonpbv4.SolanaAccountId{
				Value: tokenAccounts[i],
			},
			Balance: int64(i) * 10,
			Owner: &commonpbv4.SolanaAccountId{
				Value: priv.Public(),
			},
			CloseAuthority: &commonpbv4.SolanaAccountId{
				Value: closeAuthorities[i],
			},
		}
		env.v4Server.TokenAccounts[ownerKey] = append(env.v4Server.TokenAccounts[ownerKey], &commonpbv4.SolanaAccountId{
			Value: tokenAccounts[i],
		})
	}
	env.v4Server.Mux.Unlock()

	// Ensure the initial resolve returns the correct accounts
	accounts, err := env.internal.ResolveTokenAccounts(context.Background(), priv.Public(), true)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(accounts))
	env.v4Server.Mux.Lock()
	for _, a := range accounts {
		var found bool
		for i, e := range tokenAccounts {
			if bytes.Equal(a.AccountId.Value, e) {
				assert.EqualValues(t, i*10, a.Balance)
				found = true
				break
			}
		}
		assert.True(t, found)
	}
	assert.Equal(t, 0, len(env.v4Server.Submits))
	env.v4Server.Mux.Unlock()

	txID, err := env.client.MergeTokenAccounts(context.Background(), priv, false, WithSubsidizer(kin.PrivateKey(otherSubsidizerPriv)))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(env.v4Server.Submits))

	var tx solana.Transaction
	assert.NoError(t, tx.Unmarshal(env.v4Server.Submits[0].Transaction.Value))
	assert.Equal(t, tx.Signature(), txID)
	assert.True(t, ed25519.Verify(otherSubsidizer, tx.Message.Marshal(), tx.Signature()))

	parsed, err := kin.ParseTransaction(tx, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsed.Regions))
	assert.Equal(t, 0, len(parsed.Regions[0].Creations))
	assert.Equal(t, 3, len(parsed.Regions[0].Transfers))
	assert.Equal(t, 2, len(parsed.Regions[0].Closures))

	for _, xfer := range parsed.Regions[0].Transfers {
		assert.EqualValues(t, priv.Public(), xfer.Owner)
		assert.EqualValues(t, accounts[0].AccountId.Value, xfer.Destination)

		for i, tc := range tokenAccounts {
			if bytes.Equal(tc, xfer.Source) {
				assert.EqualValues(t, i*10, xfer.Amount)
			}
		}
	}

	for _, closure := range parsed.Regions[0].Closures {
		assert.False(t, bytes.Equal(closure.Account, accounts[0].AccountId.Value))

		for i, tc := range tokenAccounts {
			if bytes.Equal(tc, closure.Account) {
				assert.EqualValues(t, closeAuthorities[i], closure.Destination)
				assert.EqualValues(t, closeAuthorities[i], closure.Owner)
			}
		}
	}
}

func TestClient_SubmitPayment(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)
	dest, err := kin.NewPrivateKey()
	require.NoError(t, err)

	setServiceConfigResp(t, env.v4Server, true)

	for _, acc := range [][]byte{sender, dest} {
		require.NoError(t, env.client.CreateAccount(context.Background(), acc))
	}

	randId := uuid.New()
	dedupeId := randId[:]
	payments := []Payment{
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
			DedupeID:    dedupeId,
		},
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
			Memo:        "1-test",
		},
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
			Invoice: &commonpb.Invoice{
				Items: []*commonpb.Invoice_LineItem{
					{
						Title:  "test",
						Amount: 11,
					},
				},
			},
		},
	}

	for _, p := range payments {
		txID, err := env.client.SubmitPayment(context.Background(), p)
		assert.NotNil(t, txID)
		assert.NoError(t, err)

		func() {
			env.v4Server.Mux.Lock()
			defer env.v4Server.Mux.Unlock()
			defer func() { env.v4Server.Submits = nil }()

			assert.Len(t, env.v4Server.Submits, 1)

			req := env.v4Server.Submits[0]
			assert.Equal(t, p.DedupeID, req.DedupeId)

			tx := solana.Transaction{}
			assert.NoError(t, tx.Unmarshal(req.Transaction.Value))
			assert.Len(t, tx.Signatures, 2)
			assert.EqualValues(t, txID, tx.Signatures[0][:])
			assert.True(t, ed25519.Verify(ed25519.PublicKey(sender.Public()), tx.Message.Marshal(), tx.Signatures[1][:]))

			assert.Len(t, tx.Message.Instructions, 2)

			if p.Memo != "" {
				memoInstr, err := memo.DecompileMemo(tx.Message, 0)
				require.NoError(t, err)
				assert.Equal(t, p.Memo, string(memoInstr.Data))
			} else if p.Invoice != nil {
				invoiceList := &commonpb.InvoiceList{
					Invoices: []*commonpb.Invoice{p.Invoice},
				}
				ilBytes, err := proto.Marshal(invoiceList)
				require.NoError(t, err)
				ilHash := sha256.Sum224(ilBytes)

				memoInstruction, err := memo.DecompileMemo(tx.Message, 0)
				require.NoError(t, err)

				m, err := kin.MemoFromBase64String(string(memoInstruction.Data), true)
				require.NoError(t, err)

				assert.Equal(t, kin.TransactionTypeSpend, m.TransactionType())
				assert.EqualValues(t, 1, m.AppIndex())
				assert.EqualValues(t, ilHash[:], m.ForeignKey()[:28])
				assert.True(t, proto.Equal(invoiceList, req.InvoiceList))
			} else {
				memoInstr, err := memo.DecompileMemo(tx.Message, 0)
				require.NoError(t, err)

				m, err := kin.MemoFromBase64String(string(memoInstr.Data), true)
				require.NoError(t, err)

				assert.Equal(t, kin.TransactionTypeSpend, m.TransactionType())
				assert.EqualValues(t, 1, m.AppIndex())
				assert.EqualValues(t, make([]byte, 29), m.ForeignKey())
			}

			transferInstr, err := token.DecompileTransfer(tx.Message, 1)
			require.NoError(t, err)

			assert.EqualValues(t, sender.Public(), transferInstr.Source)
			assert.EqualValues(t, dest.Public(), transferInstr.Destination)
			assert.EqualValues(t, sender.Public(), transferInstr.Owner)
			assert.EqualValues(t, p.Quarks, transferInstr.Amount)
		}()
	}

	env.v4Server.Mux.Lock()
	env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
		{
			Result: transactionpbv4.SubmitTransactionResponse_INVOICE_ERROR,
			InvoiceErrors: []*commonpb.InvoiceError{
				{
					Invoice: payments[2].Invoice,
					Reason:  commonpb.InvoiceError_ALREADY_PAID,
				},
			},
		},
		{
			Result: transactionpbv4.SubmitTransactionResponse_INVOICE_ERROR,
			InvoiceErrors: []*commonpb.InvoiceError{
				{
					Invoice: payments[2].Invoice,
					Reason:  commonpb.InvoiceError_WRONG_DESTINATION,
				},
			},
		},
		{
			Result: transactionpbv4.SubmitTransactionResponse_INVOICE_ERROR,
			InvoiceErrors: []*commonpb.InvoiceError{
				{
					Invoice: payments[2].Invoice,
					Reason:  commonpb.InvoiceError_SKU_NOT_FOUND,
				},
			},
		},
	}
	env.v4Server.Mux.Unlock()

	for _, e := range []error{ErrAlreadyPaid, ErrWrongDestination, ErrSKUNotFound} {
		txID, err := env.client.SubmitPayment(context.Background(), payments[2])
		assert.NotNil(t, txID)
		assert.Equal(t, e, err)
	}

	env.v4Server.Mux.Lock()
	env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
		{
			Result: transactionpbv4.SubmitTransactionResponse_FAILED,
			TransactionError: &commonpbv4.TransactionError{
				Reason: commonpbv4.TransactionError_UNAUTHORIZED,
				Raw:    []byte("rawerror"),
			},
		},
	}
	env.v4Server.Mux.Unlock()

	txID, err := env.client.SubmitPayment(context.Background(), payments[2])
	assert.NotNil(t, txID)
	assert.Equal(t, ErrInvalidSignature, err)
}

func TestClient_SubmitPayment_SenderCreate(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)
	dest, err := kin.NewPrivateKey()
	require.NoError(t, err)

	mint, _, _ := setServiceConfigResp(t, env.v4Server, true)
	require.NoError(t, env.client.CreateAccount(context.Background(), sender))

	randId := uuid.New()
	dedupeId := randId[:]
	payments := []Payment{
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
			DedupeID:    dedupeId,
		},
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
			Memo:        "1-test",
		},
		{
			Sender:      sender,
			Destination: dest.Public(),
			Type:        kin.TransactionTypeSpend,
			Quarks:      11,
			Invoice: &commonpb.Invoice{
				Items: []*commonpb.Invoice_LineItem{
					{
						Title:  "test",
						Amount: 11,
					},
				},
			},
		},
	}

	// Assert sender create is disabled by default.
	for _, p := range payments {
		env.v4Server.Mux.Lock()
		// We require the error twice: once for the first submission (pre-resovle),
		// and the second submission (post-resolve)
		env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
			{
				Result: transactionpbv4.SubmitTransactionResponse_FAILED,
				TransactionError: &commonpbv4.TransactionError{
					Reason: commonpbv4.TransactionError_INVALID_ACCOUNT,
					Raw:    []byte{0},
				},
			},
			{
				Result: transactionpbv4.SubmitTransactionResponse_FAILED,
				TransactionError: &commonpbv4.TransactionError{
					Reason: commonpbv4.TransactionError_INVALID_ACCOUNT,
					Raw:    []byte{0},
				},
			},
		}
		env.v4Server.Mux.Unlock()

		_, err := env.client.SubmitPayment(context.Background(), p)
		assert.Equal(t, ErrAccountDoesNotExist, err)
	}

	// Assert that the creation goes through
	for _, p := range payments {
		env.v4Server.Mux.Lock()
		env.v4Server.Submits = nil
		env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
			{
				Result: transactionpbv4.SubmitTransactionResponse_FAILED,
				TransactionError: &commonpbv4.TransactionError{
					Reason: commonpbv4.TransactionError_INVALID_ACCOUNT,
					Raw:    []byte{0},
				},
			},
		}
		env.v4Server.Mux.Unlock()

		id, err := env.client.SubmitPayment(context.Background(), p, WithSenderCreate())
		assert.NoError(t, err)
		assert.NotNil(t, id)

		assert.Equal(t, 2, len(env.v4Server.Submits))

		var tx solana.Transaction
		assert.NoError(t, tx.Unmarshal(env.v4Server.Submits[0].Transaction.Value))
		parsed, err := kin.ParseTransaction(tx, nil)
		assert.NoError(t, err)

		assert.Equal(t, 2, len(parsed.Regions))
		assert.Equal(t, 0, len(parsed.Regions[1].Creations))
		assert.Equal(t, 1, len(parsed.Regions[1].Transfers))

		assert.NoError(t, tx.Unmarshal(env.v4Server.Submits[1].Transaction.Value))
		parsed, err = kin.ParseTransaction(tx, nil)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(parsed.Regions))
		assert.Equal(t, 1, len(parsed.Regions[1].Creations))
		assert.Equal(t, 1, len(parsed.Regions[1].Transfers))

		c := parsed.Regions[1].Creations[0]
		assert.EqualValues(t, c.Create.Address, c.Initialize.Account)
		assert.EqualValues(t, mint, c.Initialize.Mint)
		assert.EqualValues(t, c.Initialize.Account, c.AccountHolder.CurrentAuthority)
		assert.EqualValues(t, dest.Public(), c.AccountHolder.NewAuthority)

		xfer := parsed.Regions[1].Transfers[0]
		assert.EqualValues(t, p.Quarks, xfer.Amount)
		assert.EqualValues(t, c.Initialize.Account, xfer.Destination)
		assert.EqualValues(t, sender.Public(), xfer.Owner)
	}
}

func TestClient_SubmitPaymentNoServiceSubsidizer(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)
	dest, err := kin.NewPrivateKey()
	require.NoError(t, err)
	appSubsidizer, err := kin.NewPrivateKey()
	require.NoError(t, err)

	setServiceConfigResp(t, env.v4Server, true)
	for _, acc := range [][]byte{sender, dest, appSubsidizer} {
		require.NoError(t, env.client.CreateAccount(context.Background(), acc))
	}

	env.internal.serviceConfig = nil // reset cache
	setServiceConfigResp(t, env.v4Server, false)

	p := Payment{
		Sender:      sender,
		Destination: dest.Public(),
		Type:        kin.TransactionTypeSpend,
		Quarks:      11,
	}

	txID, err := env.client.SubmitPayment(context.Background(), p)
	assert.Equal(t, ErrNoSubsidizer, err)
	assert.Nil(t, txID)

	txID, err = env.client.SubmitPayment(context.Background(), p, WithSubsidizer(appSubsidizer))
	require.NoError(t, err)
	require.NotNil(t, txID)

	env.v4Server.Mux.Lock()
	defer env.v4Server.Mux.Unlock()

	assert.Len(t, env.v4Server.Submits, 1)

	tx := solana.Transaction{}
	assert.NoError(t, tx.Unmarshal(env.v4Server.Submits[0].Transaction.Value))
	assert.Len(t, tx.Signatures, 2)
	assert.True(t, ed25519.Verify(ed25519.PublicKey(appSubsidizer.Public()), tx.Message.Marshal(), tx.Signatures[0][:]))
	assert.True(t, ed25519.Verify(ed25519.PublicKey(sender.Public()), tx.Message.Marshal(), tx.Signatures[1][:]))

	assert.Len(t, tx.Message.Instructions, 2)

	memoInstr, err := memo.DecompileMemo(tx.Message, 0)
	require.NoError(t, err)

	m, err := kin.MemoFromBase64String(string(memoInstr.Data), true)
	require.NoError(t, err)

	assert.Equal(t, kin.TransactionTypeSpend, m.TransactionType())
	assert.EqualValues(t, 1, m.AppIndex())
	assert.EqualValues(t, make([]byte, 29), m.ForeignKey())

	transferInstr, err := token.DecompileTransfer(tx.Message, 1)
	require.NoError(t, err)

	assert.EqualValues(t, sender.Public(), transferInstr.Source)
	assert.EqualValues(t, dest.Public(), transferInstr.Destination)
	assert.EqualValues(t, sender.Public(), transferInstr.Owner)
	assert.EqualValues(t, p.Quarks, transferInstr.Amount)
}

func TestClient_SubmitPaymentKin4AccountResolution(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	mint, _, _ := setServiceConfigResp(t, env.v4Server, true)

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)
	dest, err := kin.NewPrivateKey()
	require.NoError(t, err)
	resolvedSender, err := token.GetAssociatedAccount(ed25519.PublicKey(sender.Public()), mint)
	require.NoError(t, err)
	resolvedDest, err := token.GetAssociatedAccount(ed25519.PublicKey(dest.Public()), mint)
	require.NoError(t, err)

	for _, acc := range [][]byte{sender, dest} {
		require.NoError(t, env.client.CreateAccount(context.Background(), acc))
	}

	p := Payment{
		Sender:      sender,
		Destination: dest.Public(),
		Type:        kin.TransactionTypeSpend,
		Quarks:      11,
	}

	// Test Preferred Account Resolution
	env.v4Server.Mux.Lock()
	env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
		{
			Result: transactionpbv4.SubmitTransactionResponse_FAILED,
			TransactionError: &commonpbv4.TransactionError{
				Reason: commonpbv4.TransactionError_INVALID_ACCOUNT,
				Raw:    []byte("rawerror"),
			},
		},
	}
	env.v4Server.Mux.Unlock()

	txID, err := env.client.SubmitPayment(context.Background(), p, WithAccountResolution(AccountResolutionPreferred), WithDestResolution(AccountResolutionPreferred))
	require.NoError(t, err)
	assert.NotNil(t, txID)

	env.v4Server.Mux.Lock()
	assert.Len(t, env.v4Server.Submits, 2)
	for i, submit := range env.v4Server.Submits {
		tx := solana.Transaction{}
		assert.NoError(t, tx.Unmarshal(submit.Transaction.Value))
		assert.Len(t, tx.Signatures, 2)
		assert.True(t, ed25519.Verify(ed25519.PublicKey(sender.Public()), tx.Message.Marshal(), tx.Signatures[1][:]))

		if i == 1 {
			assert.EqualValues(t, txID, tx.Signatures[0][:])
		} else {
			assert.NotEqual(t, txID, tx.Signatures[0][:])
		}

		assert.Len(t, tx.Message.Instructions, 2)

		memoInstr, err := memo.DecompileMemo(tx.Message, 0)
		require.NoError(t, err)

		m, err := kin.MemoFromBase64String(string(memoInstr.Data), true)
		require.NoError(t, err)

		assert.Equal(t, kin.TransactionTypeSpend, m.TransactionType())
		assert.EqualValues(t, 1, m.AppIndex())
		assert.EqualValues(t, make([]byte, 29), m.ForeignKey())

		transferInstr, err := token.DecompileTransfer(tx.Message, 1)
		require.NoError(t, err)

		if i == 0 {
			assert.EqualValues(t, sender.Public(), transferInstr.Source)
			assert.EqualValues(t, dest.Public(), transferInstr.Destination)
		} else {
			assert.EqualValues(t, resolvedSender, transferInstr.Source)
			assert.EqualValues(t, resolvedDest, transferInstr.Destination)
		}
		assert.EqualValues(t, sender.Public(), transferInstr.Owner)
		assert.EqualValues(t, p.Quarks, transferInstr.Amount)
	}
	env.v4Server.Mux.Unlock()

	// Test Exact Account Resolution
	env.v4Server.Mux.Lock()
	env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
		{
			Result: transactionpbv4.SubmitTransactionResponse_FAILED,
			TransactionError: &commonpbv4.TransactionError{
				Reason: commonpbv4.TransactionError_INVALID_ACCOUNT,
				Raw:    []byte("rawerror"),
			},
		},
	}
	env.v4Server.Mux.Unlock()

	txID, err = env.client.SubmitPayment(context.Background(), p, WithAccountResolution(AccountResolutionExact), WithDestResolution(AccountResolutionExact))
	assert.EqualValues(t, ErrAccountDoesNotExist, err)
	assert.NotNil(t, txID)
}

func TestClient_SubmitEarnBatch(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)

	earnAccounts := make([]kin.PrivateKey, 15)
	for i := 0; i < len(earnAccounts); i++ {
		dest, err := kin.NewPrivateKey()
		require.NoError(t, err)
		earnAccounts[i] = dest
	}

	setServiceConfigResp(t, env.v4Server, true)

	for _, acc := range append([]kin.PrivateKey{sender}, earnAccounts...) {
		require.NoError(t, env.client.CreateAccount(context.Background(), acc))
	}

	var earns []Earn
	for i, r := range earnAccounts {
		earns = append(earns, Earn{
			Destination: r.Public(),
			Quarks:      int64(i) + 1,
		})
	}
	var invoiceEarns []Earn
	for i, r := range earnAccounts {
		invoiceEarns = append(invoiceEarns, Earn{
			Destination: r.Public(),
			Quarks:      int64(i) + 1,
			Invoice: &commonpb.Invoice{
				Items: []*commonpb.Invoice_LineItem{
					{
						Title:  "Test",
						Amount: int64(i) + 1,
					},
				},
			},
		})
	}

	randId := uuid.New()
	batches := []EarnBatch{
		{
			Sender:   sender,
			Earns:    earns,
			DedupeID: randId[:],
		},
		{
			Sender: sender,
			Earns:  earns,
			Memo:   "somememo",
		},
		{
			Sender: sender,
			Earns:  invoiceEarns,
		},
	}

	for _, b := range batches {
		result, err := env.client.SubmitEarnBatch(context.Background(), b)
		assert.NoError(t, err)
		assert.NotNil(t, result.TxID)
		assert.Nil(t, result.TxError)
		assert.Nil(t, result.EarnErrors)

		func() {
			env.v4Server.Mux.Lock()
			defer env.v4Server.Mux.Unlock()
			defer func() { env.v4Server.Submits = nil }()

			assert.Len(t, env.v4Server.Submits, 1)

			req := env.v4Server.Submits[0]
			assert.Equal(t, b.DedupeID, req.DedupeId)

			tx := solana.Transaction{}
			assert.NoError(t, tx.Unmarshal(req.Transaction.Value))
			assert.Len(t, tx.Signatures, 2)
			assert.EqualValues(t, result.TxID, tx.Signatures[0][:])
			assert.True(t, ed25519.Verify(ed25519.PublicKey(sender.Public()), tx.Message.Marshal(), tx.Signatures[1][:]))

			if b.Memo != "" {
				memoInstr, err := memo.DecompileMemo(tx.Message, 0)
				require.NoError(t, err)
				assert.Equal(t, b.Memo, string(memoInstr.Data))
			} else if b.Earns[0].Invoice != nil {
				invoiceList := &commonpb.InvoiceList{
					Invoices: make([]*commonpb.Invoice, 0, 15),
				}

				for j := 0; j < 15; j++ {
					invoiceList.Invoices = append(invoiceList.Invoices, b.Earns[j].Invoice)
				}

				ilBytes, err := proto.Marshal(invoiceList)
				require.NoError(t, err)
				ilHash := sha256.Sum224(ilBytes)

				memoInstruction, err := memo.DecompileMemo(tx.Message, 0)
				require.NoError(t, err)

				m, err := kin.MemoFromBase64String(string(memoInstruction.Data), true)
				require.NoError(t, err)

				assert.Equal(t, kin.TransactionTypeEarn, m.TransactionType())
				assert.EqualValues(t, 1, m.AppIndex())
				assert.EqualValues(t, ilHash[:], m.ForeignKey()[:28])
				assert.True(t, proto.Equal(invoiceList, req.InvoiceList))
			} else {
				memoInstr, err := memo.DecompileMemo(tx.Message, 0)
				require.NoError(t, err)

				m, err := kin.MemoFromBase64String(string(memoInstr.Data), true)
				require.NoError(t, err)

				assert.Equal(t, kin.TransactionTypeEarn, m.TransactionType())
				assert.EqualValues(t, 1, m.AppIndex())
				assert.EqualValues(t, make([]byte, 29), m.ForeignKey())
			}

			assert.Len(t, tx.Message.Instructions, 15+1)
			for j := 0; j < 15; j++ {
				transferInstr, err := token.DecompileTransfer(tx.Message, j+1)
				require.NoError(t, err)

				earn := b.Earns[j]
				assert.EqualValues(t, sender.Public(), transferInstr.Source)
				assert.EqualValues(t, earn.Destination, transferInstr.Destination)
				assert.EqualValues(t, sender.Public(), transferInstr.Owner)
				assert.EqualValues(t, earn.Quarks, transferInstr.Amount)
			}
		}()
	}

	// Ensure context cancellation works correctly.
	ctx, cancelFunc := context.WithCancel(context.Background())
	cancelFunc()
	result, err := env.client.SubmitEarnBatch(ctx, batches[0])
	assert.Error(t, err)
	assert.Nil(t, result.TxID)
	assert.Nil(t, result.TxError)
	assert.Nil(t, result.EarnErrors)

	env.v4Server.Mux.Lock()
	env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
		{
			Result: transactionpbv4.SubmitTransactionResponse_FAILED,
			TransactionError: &commonpbv4.TransactionError{
				Reason:           commonpbv4.TransactionError_UNAUTHORIZED,
				InstructionIndex: 0,
				Raw:              []byte("rawerror"),
			},
		},
	}
	env.v4Server.Mux.Unlock()

	result, err = env.client.SubmitEarnBatch(context.Background(), batches[0])
	assert.Nil(t, err)
	assert.NotNil(t, result.TxID)
	assert.Equal(t, ErrInvalidSignature, result.TxError)
	assert.Nil(t, result.EarnErrors)
}

func TestClient_SubmitEarnBatchNoServiceSubsidizer(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)
	appSubsidizer, err := kin.NewPrivateKey()
	require.NoError(t, err)

	earns := make([]Earn, 15)
	earnAccounts := make([]kin.PrivateKey, 15)
	for i := 0; i < len(earnAccounts); i++ {
		dest, err := kin.NewPrivateKey()
		require.NoError(t, err)
		earnAccounts[i] = dest

		earns[i] = Earn{
			Destination: dest.Public(),
			Quarks:      int64(i) + 1,
		}
	}

	setServiceConfigResp(t, env.v4Server, true)
	for _, acc := range append([]kin.PrivateKey{sender, appSubsidizer}, earnAccounts...) {
		require.NoError(t, env.client.CreateAccount(context.Background(), acc))
	}

	env.internal.serviceConfig = nil // reset cache
	setServiceConfigResp(t, env.v4Server, false)

	b := EarnBatch{
		Sender: sender,
		Earns:  earns,
	}

	result, err := env.client.SubmitEarnBatch(context.Background(), b)
	assert.Equal(t, ErrNoSubsidizer, err)
	assert.Equal(t, EarnBatchResult{}, result)

	result, err = env.client.SubmitEarnBatch(context.Background(), b, WithSubsidizer(appSubsidizer))
	assert.NoError(t, err)
	assert.NotNil(t, result.TxID)
	assert.Nil(t, result.TxError)
	assert.Nil(t, result.EarnErrors)

	env.v4Server.Mux.Lock()
	defer env.v4Server.Mux.Unlock()

	assert.Len(t, env.v4Server.Submits, 1)

	req := env.v4Server.Submits[0]

	tx := solana.Transaction{}
	assert.NoError(t, tx.Unmarshal(req.Transaction.Value))
	assert.Len(t, tx.Signatures, 2)
	assert.True(t, ed25519.Verify(ed25519.PublicKey(appSubsidizer.Public()), tx.Message.Marshal(), tx.Signatures[0][:]))
	assert.True(t, ed25519.Verify(ed25519.PublicKey(sender.Public()), tx.Message.Marshal(), tx.Signatures[1][:]))

	memoInstr, err := memo.DecompileMemo(tx.Message, 0)
	require.NoError(t, err)

	m, err := kin.MemoFromBase64String(string(memoInstr.Data), true)
	require.NoError(t, err)

	assert.Equal(t, kin.TransactionTypeEarn, m.TransactionType())
	assert.EqualValues(t, 1, m.AppIndex())
	assert.EqualValues(t, make([]byte, 29), m.ForeignKey())

	assert.Len(t, tx.Message.Instructions, 15+1)
	for j := 0; j < 15; j++ {
		transferInstr, err := token.DecompileTransfer(tx.Message, j+1)
		require.NoError(t, err)

		earn := b.Earns[+j]
		assert.EqualValues(t, sender.Public(), transferInstr.Source)
		assert.EqualValues(t, earn.Destination, transferInstr.Destination)
		assert.EqualValues(t, sender.Public(), transferInstr.Owner)
		assert.EqualValues(t, earn.Quarks, transferInstr.Amount)
	}
}

func TestClient_SubmitEarnBatchAccountResolution(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	mint, _, _ := setServiceConfigResp(t, env.v4Server, true)

	sender, err := kin.NewPrivateKey()
	require.NoError(t, err)
	resolvedSender, err := token.GetAssociatedAccount(ed25519.PublicKey(sender.Public()), mint)
	require.NoError(t, err)

	// Test Preferred Account Resolution
	env.v4Server.Mux.Lock()
	env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
		{
			Result: transactionpbv4.SubmitTransactionResponse_FAILED,
			TransactionError: &commonpbv4.TransactionError{
				Reason: commonpbv4.TransactionError_INVALID_ACCOUNT,
				Raw:    []byte("rawerror"),
			},
		},
	}
	env.v4Server.Mux.Unlock()

	earns := make([]Earn, 15)
	earnAccounts := make([]kin.PrivateKey, 15)
	resolvedEarnAccounts := make([]kin.PublicKey, 15)
	for i := 0; i < len(earnAccounts); i++ {
		dest, err := kin.NewPrivateKey()
		require.NoError(t, err)
		earnAccounts[i] = dest

		earns[i] = Earn{
			Destination: dest.Public(),
			Quarks:      int64(i) + 1,
		}

		resolvedDest, err := token.GetAssociatedAccount(ed25519.PublicKey(dest.Public()), mint)
		require.NoError(t, err)

		resolvedEarnAccounts[i] = kin.PublicKey(resolvedDest)
	}

	for _, acc := range append([]kin.PrivateKey{sender}, earnAccounts...) {
		require.NoError(t, env.client.CreateAccount(context.Background(), acc))
	}
	b := EarnBatch{
		Sender: sender,
		Earns:  earns,
	}

	result, err := env.client.SubmitEarnBatch(context.Background(), b, WithAccountResolution(AccountResolutionPreferred), WithDestResolution(AccountResolutionPreferred))
	assert.NoError(t, err)
	assert.NotNil(t, result.TxID)
	assert.Nil(t, result.TxError)
	assert.Nil(t, result.EarnErrors)

	env.v4Server.Mux.Lock()

	assert.Len(t, env.v4Server.Submits, 2)
	for i, s := range env.v4Server.Submits {
		resolved := (i % 2) == 1

		tx := solana.Transaction{}
		assert.NoError(t, tx.Unmarshal(s.Transaction.Value))
		assert.Len(t, tx.Signatures, 2)
		assert.True(t, ed25519.Verify(ed25519.PublicKey(sender.Public()), tx.Message.Marshal(), tx.Signatures[1][:]))

		if i == 1 {
			assert.EqualValues(t, result.TxID, tx.Signatures[0][:])
		} else {
			assert.NotEqual(t, result.TxID, tx.Signatures[0][:])
		}

		memoInstr, err := memo.DecompileMemo(tx.Message, 0)
		require.NoError(t, err)

		m, err := kin.MemoFromBase64String(string(memoInstr.Data), true)
		require.NoError(t, err)

		assert.Equal(t, kin.TransactionTypeEarn, m.TransactionType())
		assert.EqualValues(t, 1, m.AppIndex())
		assert.EqualValues(t, make([]byte, 29), m.ForeignKey())

		assert.Len(t, tx.Message.Instructions, 15+1)
		for j := 0; j < 15; j++ {
			transferInstr, err := token.DecompileTransfer(tx.Message, j+1)
			require.NoError(t, err)

			earn := b.Earns[j]
			if resolved {
				require.EqualValues(t, resolvedSender, transferInstr.Source)
				require.EqualValues(t, resolvedEarnAccounts[j], transferInstr.Destination)
			} else {
				require.EqualValues(t, sender.Public(), transferInstr.Source)
				require.EqualValues(t, earnAccounts[j].Public(), transferInstr.Destination)
			}
			require.EqualValues(t, sender.Public(), transferInstr.Owner)
			require.EqualValues(t, earn.Quarks, transferInstr.Amount)
		}
	}
	env.v4Server.Mux.Unlock()

	// Test Exact Account Resolution
	env.v4Server.Mux.Lock()
	env.v4Server.Submits = nil
	env.v4Server.SubmitResponses = []*transactionpbv4.SubmitTransactionResponse{
		{
			Result: transactionpbv4.SubmitTransactionResponse_FAILED,
			TransactionError: &commonpbv4.TransactionError{
				Reason: commonpbv4.TransactionError_INVALID_ACCOUNT,
				Raw:    []byte("rawerror"),
			},
		},
	}
	env.v4Server.Mux.Unlock()

	result, err = env.client.SubmitEarnBatch(context.Background(), b, WithAccountResolution(AccountResolutionExact), WithDestResolution(AccountResolutionExact))
	require.Nil(t, err)
	assert.NotNil(t, result.TxID)
	assert.Equal(t, ErrAccountDoesNotExist, result.TxError)
	assert.Nil(t, result.EarnErrors)

	env.v4Server.Mux.Lock()
	defer env.v4Server.Mux.Unlock()

	assert.Len(t, env.v4Server.Submits, 1)
}

func TestClient_RequestAirdropWrongEnv(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	priv, err := kin.NewPrivateKey()
	require.NoError(t, err)

	env.client.env = EnvironmentProd
	txID, err := env.client.RequestAirdrop(context.Background(), priv.Public(), 2)
	assert.Error(t, err)
	assert.Nil(t, txID)
}

func TestClient_RequestAirdrop(t *testing.T) {
	env, cleanup := setup(t)
	defer cleanup()

	priv, err := kin.NewPrivateKey()
	require.NoError(t, err)

	mint, _, _ := setServiceConfigResp(t, env.v4Server, true)

	err = env.client.CreateAccount(context.Background(), priv)
	assert.NoError(t, err)

	txID, err := env.client.RequestAirdrop(context.Background(), priv.Public(), 2)
	assert.Equal(t, ErrAccountDoesNotExist, err)
	assert.Nil(t, txID)

	tokenAcc, err := token.GetAssociatedAccount(ed25519.PublicKey(priv.Public()), mint)
	require.NoError(t, err)

	txID, err = env.client.RequestAirdrop(context.Background(), kin.PublicKey(tokenAcc), 2)
	require.NoError(t, err)
	assert.NotNil(t, txID)
}
