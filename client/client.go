package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/agora-common/retry"
	"github.com/kinecosystem/agora-common/retry/backoff"
	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/solana/memo"
	"github.com/kinecosystem/agora-common/solana/system"
	"github.com/kinecosystem/agora-common/solana/token"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"
	commonpbv4 "github.com/kinecosystem/agora-api/genproto/common/v4"
	transactionpbv4 "github.com/kinecosystem/agora-api/genproto/transaction/v4"
)

// Environment specifies the desired Kin environment to use.
type Environment string

const (
	EnvironmentTest Environment = "test"
	EnvironmentProd Environment = "prod"

	MaxBatchSize = 15
)

type Client interface {
	// CreateAccount creates a kin account.
	CreateAccount(ctx context.Context, key kin.PrivateKey, opts ...SolanaOption) (err error)

	// GetBalance returns the balance of a kin account in quarks.
	//
	// ErrAccountDoesNotExist is returned if no account exists.
	GetBalance(ctx context.Context, account kin.PublicKey, opts ...SolanaOption) (quarks int64, err error)

	// ResolveTokenAccounts resolves the token accounts owned by an account on Kin 4.
	ResolveTokenAccounts(ctx context.Context, account kin.PublicKey) ([]kin.PublicKey, error)

	// MergeTokenAccounts merges the balances of all the token accounts owned by the
	// specified account into a single token account (the first one returned by ResolveTokenAccounts).
	//
	// If createAssociatedAccount is set, the operation will create the associated account
	// (if it does not exist), and the funds will be sent to the associated account.
	MergeTokenAccounts(ctx context.Context, account kin.PrivateKey, createAssociatedAccount bool, opts ...SolanaOption) (txID []byte, err error)

	// GetTransaction returns the TransactionData for a given transaction hash.
	//
	// ErrTransactionNotFound is returned if no transaction exists for the hash.
	GetTransaction(ctx context.Context, txHash []byte, opts ...SolanaOption) (data TransactionData, err error)

	// SubmitPayment submits a single payment to a specified kin account.
	SubmitPayment(ctx context.Context, payment Payment, opts ...SolanaOption) (txHash []byte, err error)

	// SubmitEarnBatch submits a batch of earn payments.
	//
	// The batch may be done in on or more transactions.
	SubmitEarnBatch(ctx context.Context, batch EarnBatch, opts ...SolanaOption) (result EarnBatchResult, err error)

	// Requests an airdrop of Kin to a Kin token account. Only available on the Kin 4 test environment.
	RequestAirdrop(ctx context.Context, publicKey kin.PublicKey, quarks uint64, opts ...SolanaOption) (txID []byte, err error)
}

type client struct {
	internal *InternalClient
	opts     clientOpts

	env Environment
}

type clientOpts struct {
	maxRetries         uint
	maxSequenceRetries uint
	minDelay           time.Duration
	maxDelay           time.Duration

	cc       *grpc.ClientConn
	endpoint string
	appIndex uint16

	defaultCommitment commonpbv4.Commitment
}

// ClientOption configures a Client.
type ClientOption func(*clientOpts)

// WithAppIndex specifies the app index to use when
// submitting transactions with Invoices, _or_ to use
// the non-text based memo format.
func WithAppIndex(index uint16) ClientOption {
	return func(o *clientOpts) {
		o.appIndex = index
	}
}

// WithGRPC specifies a grpc.ClientConn to use.
//
// It cannot be used alongside WithEndpoint.
func WithGRPC(cc *grpc.ClientConn) ClientOption {
	return func(o *clientOpts) {
		o.cc = cc
	}
}

// WithEndpoint specifies an endpoint to use.
//
// It cannot be used alongside WithGRPC.
func WithEndpoint(endpoint string) ClientOption {
	return func(o *clientOpts) {
		o.endpoint = endpoint
	}
}

// WithMaxRetries specifies the maximum number of retries the
// client will perform for transient errors.
func WithMaxRetries(maxRetries uint) ClientOption {
	return func(o *clientOpts) {
		o.maxRetries = maxRetries
	}
}

// WithMaxNonceRetries specifies the maximum number of times
// the client will attempt to regenerate a nonce and retry
// a transaction.
//
// This is independent from WithMaxRetries.
func WithMaxNonceRetries(maxSequenceRetries uint) ClientOption {
	return func(o *clientOpts) {
		o.maxSequenceRetries = maxSequenceRetries
	}
}

// WithMinDelay specifies the minimum delay when retrying.
func WithMinDelay(minDelay time.Duration) ClientOption {
	return func(o *clientOpts) {
		o.minDelay = minDelay
	}
}

// WithMaxDelay specifies the maximum delay when retrying.
func WithMaxDelay(maxDelay time.Duration) ClientOption {
	return func(o *clientOpts) {
		o.maxDelay = maxDelay
	}
}

// WithDefaultCommitment specifies a default commitment to use for Kin 4 requests.
func WithDefaultCommitment(defaultCommitment commonpbv4.Commitment) ClientOption {
	return func(o *clientOpts) {
		o.defaultCommitment = defaultCommitment
	}
}

type solanaOpts struct {
	commitment        commonpbv4.Commitment
	accountResolution AccountResolution
	destResolution    AccountResolution
	subsidizer        kin.PrivateKey
	senderCreate      bool
}

// ClientOption configures a solana-related function call.
type SolanaOption func(opts *solanaOpts)

// WithCommitment specifies a commitment to use for a Kin 4 request.
func WithCommitment(commitment commonpbv4.Commitment) SolanaOption {
	return func(o *solanaOpts) {
		o.commitment = commitment
	}
}

// WithAccountResolution specifies an account resolution to use for a Kin 4 request.
// In the case of payments/earn batches, the specified resolution will be used only for the sender.
func WithAccountResolution(resolution AccountResolution) SolanaOption {
	return func(o *solanaOpts) {
		o.accountResolution = resolution
	}
}

// WithDestResolution specifies an account resolution to use for Kin 4 payment/earn batch destinations.
func WithDestResolution(resolution AccountResolution) SolanaOption {
	return func(o *solanaOpts) {
		o.destResolution = resolution
	}
}

// WithSubsidizer specifies a subsidizer to use for a Kin 4 transaction.
func WithSubsidizer(subsidizer kin.PrivateKey) SolanaOption {
	return func(o *solanaOpts) {
		o.subsidizer = subsidizer
	}
}

// WithSenderCreate specifies that destination accounts should be created if they
// do not exist.
func WithSenderCreate() SolanaOption {
	return func(o *solanaOpts) {
		o.senderCreate = true
	}
}

// New creates a new client.
//
// todo: appIndex optional, can use string memo instead
func New(env Environment, opts ...ClientOption) (Client, error) {
	c := &client{
		opts: clientOpts{
			maxRetries:         10,
			maxSequenceRetries: 3,
			minDelay:           500 * time.Millisecond,
			maxDelay:           10 * time.Second,
			defaultCommitment:  commonpbv4.Commitment_SINGLE,
		},
	}

	for _, o := range opts {
		o(&c.opts)
	}

	var endpoint string
	switch env {
	case EnvironmentTest:
		endpoint = "api.agorainfra.dev:443"
	case EnvironmentProd:
		endpoint = "api.agorainfra.net:443"
	default:
		return nil, errors.Errorf("unknown environment: %s", env)
	}
	c.env = env

	if c.opts.cc != nil && c.opts.endpoint != "" {
		return nil, errors.New("WithGRPC and WithEndpoint cannot both be set")
	}
	if c.opts.endpoint != "" {
		endpoint = c.opts.endpoint
	}

	if c.opts.cc == nil {
		var err error
		c.opts.cc, err = grpc.Dial(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize grpc client")
		}
	}

	retrier := retry.NewRetrier(
		retry.Limit(c.opts.maxRetries),
		retry.BackoffWithJitter(backoff.BinaryExponential(c.opts.minDelay), c.opts.maxDelay, 0.1),
		retry.NonRetriableErrors(nonRetriableErrors...),
		retry.NonRetriableGRPCCodes(codes.Canceled),
	)

	c.internal = NewInternalClient(c.opts.cc, retrier)

	return c, nil
}

// CreateAccount creates a kin account.
func (c *client) CreateAccount(ctx context.Context, key kin.PrivateKey, opts ...SolanaOption) error {
	solanaOpts := solanaOpts{commitment: c.opts.defaultCommitment}
	for _, o := range opts {
		o(&solanaOpts)
	}
	_, err := retry.Retry(
		func() error {
			return c.internal.CreateSolanaAccount(ctx, key, solanaOpts.commitment, solanaOpts.subsidizer, c.opts.appIndex)
		},
		retry.Limit(c.opts.maxSequenceRetries),
		retry.RetriableErrors(ErrBadNonce),
	)
	return err
}

// GetBalance returns the balance of a kin account in quarks.
//
// ErrAccountDoesNotExist is returned if no account exists.
func (c *client) GetBalance(ctx context.Context, account kin.PublicKey, opts ...SolanaOption) (int64, error) {
	solanaOpts := solanaOpts{
		commitment:        c.opts.defaultCommitment,
		accountResolution: AccountResolutionPreferred,
	}
	for _, o := range opts {
		o(&solanaOpts)
	}

	accountInfo, err := c.internal.GetSolanaAccountInfo(ctx, account, solanaOpts.commitment)
	if err == ErrAccountDoesNotExist && solanaOpts.accountResolution == AccountResolutionPreferred {
		accountInfos, err := c.internal.ResolveTokenAccounts(ctx, account, true)
		if err != nil {
			return 0, err
		}
		if len(accountInfos) == 0 {
			return 0, ErrAccountDoesNotExist
		}

		return accountInfos[0].Balance, nil
	} else if err != nil {
		return 0, err
	}

	return accountInfo.Balance, nil
}

func (c *client) ResolveTokenAccounts(ctx context.Context, account kin.PublicKey) ([]kin.PublicKey, error) {
	accountInfos, err := c.internal.ResolveTokenAccounts(ctx, account, false)
	if err != nil {
		return nil, err
	}

	accounts := make([]kin.PublicKey, len(accountInfos))
	for i := range accountInfos {
		accounts[i] = accountInfos[i].AccountId.Value
	}
	return accounts, nil
}

func (c *client) MergeTokenAccounts(ctx context.Context, account kin.PrivateKey, createAssociatedAccount bool, opts ...SolanaOption) ([]byte, error) {
	conf := solanaOpts{
		commitment: commonpbv4.Commitment_SINGLE,
	}

	for _, o := range opts {
		o(&conf)
	}

	existingAccounts, err := c.internal.ResolveTokenAccounts(ctx, account.Public(), true)
	if err != nil {
		return nil, err
	}
	if len(existingAccounts) == 0 || !createAssociatedAccount && len(existingAccounts) == 1 {
		return nil, nil
	}

	var instructions []solana.Instruction
	dest := ed25519.PublicKey(existingAccounts[0].AccountId.Value)

	config, err := c.internal.GetServiceConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get service config")
	}

	var subsidizer ed25519.PublicKey
	signers := []kin.PrivateKey{account}

	if conf.subsidizer != nil {
		subsidizer = ed25519.PublicKey(conf.subsidizer.Public())
		signers = append(signers, conf.subsidizer)
	} else if len(config.SubsidizerAccount.Value) == ed25519.PublicKeySize {
		subsidizer = config.SubsidizerAccount.Value
	} else {
		return nil, ErrNoSubsidizer
	}

	if createAssociatedAccount {
		create, assoc, err := token.CreateAssociatedTokenAccount(
			subsidizer,
			ed25519.PublicKey(account.Public()),
			config.Token.Value,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate associated account instruction")
		}

		if !bytes.Equal(existingAccounts[0].AccountId.Value, assoc) {
			instructions = append(instructions, create)
			instructions = append(instructions, token.SetAuthority(
				assoc,
				ed25519.PublicKey(account.Public()),
				subsidizer,
				token.AuthorityTypeCloseAccount,
			))
			dest = assoc
		} else if len(existingAccounts) == 1 {
			return nil, nil
		}
	}

	for _, existing := range existingAccounts {
		if bytes.Equal(dest, existing.AccountId.Value) {
			continue
		}

		instructions = append(instructions, token.Transfer(
			existing.AccountId.Value,
			dest,
			ed25519.PublicKey(account.Public()),
			uint64(existing.Balance),
		))

		// If no close authority is set, it likely means we do not know it, and
		// can't make any assumptions.
		if existing.CloseAuthority == nil {
			continue
		}

		// If the subsidizer is the close authority, we can include the close instruction
		// as they will be ok with signing for it.
		//
		// Alternatively, if we're the close authority, we are signing it.
		var shouldClose bool
		for _, a := range [][]byte{nil, account.Public(), subsidizer} {
			if bytes.Equal(existing.CloseAuthority.Value, a) {
				shouldClose = true
				break
			}
		}

		if shouldClose {
			instructions = append(instructions, token.CloseAccount(
				existing.AccountId.Value,
				existing.CloseAuthority.Value,
				existing.CloseAuthority.Value,
			))
		}
	}

	tx := solana.NewTransaction(
		subsidizer,
		instructions...,
	)

	result, err := c.signAndSubmitTx(ctx, signers, tx, conf.commitment, nil, nil)
	if err != nil {
		return result.ID, err
	}

	return result.ID, result.Errors.TxError
}

// GetTransaction returns the TransactionData for a given transaction hash.
//
// ErrTransactionNotFound is returned if no transaction exists for the hash.
func (c *client) GetTransaction(ctx context.Context, txID []byte, opts ...SolanaOption) (TransactionData, error) {
	solanaOpts := solanaOpts{commitment: c.opts.defaultCommitment}
	for _, o := range opts {
		o(&solanaOpts)
	}

	return c.internal.GetTransaction(ctx, txID, solanaOpts.commitment)
}

// SubmitPayment sends a single payment to a specified kin account.
func (c *client) SubmitPayment(ctx context.Context, payment Payment, opts ...SolanaOption) ([]byte, error) {
	if payment.Invoice != nil && c.opts.appIndex == 0 {
		return nil, errors.New("cannot submit payment with invoices without an app index")
	}

	solanaOpts := solanaOpts{
		commitment:        c.opts.defaultCommitment,
		accountResolution: AccountResolutionPreferred,
		destResolution:    AccountResolutionPreferred,
	}
	for _, o := range opts {
		o(&solanaOpts)
	}

	var result SubmitTransactionResult
	var err error

	result, err = c.submitPaymentWithResolution(ctx, payment, solanaOpts)
	if err != nil {
		return result.ID, err
	}

	if len(result.Errors.PaymentErrors) > 0 {
		if len(result.Errors.PaymentErrors) != 1 {
			return result.ID, errors.Errorf("invalid number of payment errors. expected 0 or 1, got %d", len(result.Errors.OpErrors))
		}

		return result.ID, result.Errors.PaymentErrors[0]
	}
	if result.Errors.TxError != nil {
		return result.ID, result.Errors.TxError
	}
	if len(result.InvoiceErrors) > 0 {
		if len(result.InvoiceErrors) != 1 {
			return result.ID, errors.Errorf("invalid number of invoice errors. expected 0 or 1, got %d", len(result.InvoiceErrors))
		}

		return result.ID, invoiceErrorFromProto(result.InvoiceErrors[0])
	}

	return result.ID, nil
}

// SubmitEarnBatch submits a batch of earn payments in a single transaction.
//
// A batch is limited to 15 earns, which is roughly the max number of transfers
// that can fit inside a Solana transaction
func (c *client) SubmitEarnBatch(ctx context.Context, batch EarnBatch, opts ...SolanaOption) (result EarnBatchResult, err error) {
	solanaOpts := solanaOpts{
		commitment:        c.opts.defaultCommitment,
		accountResolution: AccountResolutionPreferred,
		destResolution:    AccountResolutionPreferred,
	}
	for _, o := range opts {
		o(&solanaOpts)
	}

	if len(batch.Earns) == 0 {
		return result, errors.New("earn batch must contain at least 1 earn")
	}
	if len(batch.Earns) > MaxBatchSize {
		return result, errors.Errorf("earn batch must not contain more than %d earns", MaxBatchSize)
	}

	// Verify that there isn't a mixed usage of Invoices and text Memos, so we can
	// fail early to reduce the chance of partial failures.
	if batch.Memo != "" {
		for _, r := range batch.Earns {
			if r.Invoice != nil {
				err = errors.New("cannot have invoice set when memo is set")
				break
			}
		}
	} else {
		if batch.Earns[0].Invoice != nil && c.opts.appIndex == 0 {
			err = errors.New("cannot submit earn batch with invoices without an app index")
		} else {
			for i := 0; i < len(batch.Earns)-1; i++ {
				if (batch.Earns[i].Invoice == nil) != (batch.Earns[i+1].Invoice == nil) {
					err = errors.New("either all or none of the earns should have an invoice set")
					break
				}
			}
		}
	}
	if err != nil {
		return result, err
	}

	config, err := c.internal.GetServiceConfig(ctx)
	if err != nil {
		return result, err
	}

	if config.GetSubsidizerAccount() == nil && solanaOpts.subsidizer == nil {
		return result, ErrNoSubsidizer
	}

	submitResult, err := c.submitEarnBatchWithResolution(ctx, batch, config, solanaOpts)
	if err != nil {
		return result, err
	}

	result.TxID = submitResult.ID
	if submitResult.Errors.TxError != nil {
		result.TxError = submitResult.Errors.TxError

		if len(submitResult.Errors.PaymentErrors) > 0 {
			result.EarnErrors = make([]EarnError, 0)
			for i, e := range submitResult.Errors.PaymentErrors {
				result.EarnErrors = append(result.EarnErrors, EarnError{
					EarnIndex: i,
					Error:     e,
				})
			}
		}
	} else if len(submitResult.InvoiceErrors) > 0 {
		result.TxError = ErrTransactionRejected
		result.EarnErrors = make([]EarnError, len(submitResult.InvoiceErrors))
		for i, e := range submitResult.InvoiceErrors {
			result.EarnErrors[i] = EarnError{
				EarnIndex: int(e.OpIndex),
				Error:     invoiceErrorFromProto(e),
			}
		}
	}

	return result, err
}

func (c *client) RequestAirdrop(ctx context.Context, publicKey kin.PublicKey, quarks uint64, opts ...SolanaOption) ([]byte, error) {
	if c.env != EnvironmentTest {
		return nil, errors.New("only available on the test environment")
	}

	solanaOpts := solanaOpts{commitment: c.opts.defaultCommitment}
	for _, o := range opts {
		o(&solanaOpts)
	}

	return c.internal.RequestAirdrop(ctx, publicKey, quarks, solanaOpts.commitment)
}

func (c *client) submitPaymentWithResolution(ctx context.Context, p Payment, solanaOpts solanaOpts) (result SubmitTransactionResult, err error) {
	config, err := c.internal.GetServiceConfig(ctx)
	if err != nil {
		return result, errors.Wrap(err, "failed to get service config")
	}

	if config.GetSubsidizerAccount() == nil && solanaOpts.subsidizer == nil {
		return SubmitTransactionResult{}, ErrNoSubsidizer
	}

	var subsidizer ed25519.PublicKey
	if solanaOpts.subsidizer != nil {
		subsidizer = ed25519.PublicKey(solanaOpts.subsidizer.Public())
	} else {
		subsidizer = config.SubsidizerAccount.GetValue()
	}

	var transferSender kin.PublicKey
	internalPayment := payment{
		Payment: p,
	}

	// Optimistically send the payment (without resolution)
	result, err = c.submitSolanaPayment(ctx, internalPayment, config, solanaOpts.commitment, transferSender, solanaOpts.subsidizer)
	if err != nil {
		return result, err
	}
	if result.Errors.TxError != ErrAccountDoesNotExist {
		return result, err
	}

	var resubmit bool
	if solanaOpts.accountResolution == AccountResolutionPreferred {
		tokenAccounts, err := c.internal.ResolveTokenAccounts(ctx, internalPayment.Sender.Public(), false)
		if err != nil {
			return result, err
		}

		if len(tokenAccounts) > 0 {
			transferSender = tokenAccounts[0].AccountId.Value
			resubmit = true
		}
	}
	if solanaOpts.destResolution == AccountResolutionPreferred {
		tokenAccounts, err := c.internal.ResolveTokenAccounts(ctx, internalPayment.Destination, false)
		if err != nil {
			return result, err
		}

		if len(tokenAccounts) > 0 {
			internalPayment.Destination = tokenAccounts[0].AccountId.Value
			resubmit = true
		} else if solanaOpts.senderCreate {
			lamports, err := c.internal.GetMinimumBalanceForRentException(ctx, token.AccountSize)
			if err != nil {
				return result, errors.Wrap(err, "failed to get minimum lamports")
			}

			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				return result, errors.Wrap(err, "failed to generate temporary key")
			}

			internalPayment.Destination = kin.PublicKey(pub)
			internalPayment.createAccountInstructions = []solana.Instruction{
				system.CreateAccount(
					subsidizer,
					pub,
					token.ProgramKey,
					lamports,
					token.AccountSize,
				),
				token.InitializeAccount(
					pub,
					config.Token.Value,
					pub,
				),
				token.SetAuthority(
					pub,
					pub,
					subsidizer,
					token.AuthorityTypeCloseAccount,
				),
				token.SetAuthority(
					pub,
					pub,
					ed25519.PublicKey(p.Destination),
					token.AuthorityTypeAccountHolder,
				),
			}
			internalPayment.createAccountSigner = priv
			resubmit = true
		}
	}

	if resubmit {
		result, err = c.submitSolanaPayment(ctx, internalPayment, config, solanaOpts.commitment, transferSender, solanaOpts.subsidizer)
	}

	return result, err
}

func (c *client) submitSolanaPayment(ctx context.Context, p payment, config *transactionpbv4.GetServiceConfigResponse, commitment commonpbv4.Commitment, transferSource kin.PublicKey, subsidizer kin.PrivateKey) (SubmitTransactionResult, error) {
	var subsidizerID kin.PublicKey
	var signers []kin.PrivateKey
	if subsidizer != nil {
		subsidizerID = subsidizer.Public()
		signers = []kin.PrivateKey{subsidizer, p.Sender}
	} else {
		subsidizerID = config.GetSubsidizerAccount().GetValue()
		signers = []kin.PrivateKey{p.Sender}
	}
	if len(p.createAccountSigner) == ed25519.PrivateKeySize {
		signers = append(signers, kin.PrivateKey(p.createAccountSigner))
	}

	var instructions []solana.Instruction
	var il *commonpb.InvoiceList

	if p.Memo != "" {
		instructions = append(instructions, memo.Instruction(p.Memo))
	} else if c.opts.appIndex > 0 {
		var fk [sha256.Size224]byte

		if p.Invoice != nil {
			il = &commonpb.InvoiceList{
				Invoices: []*commonpb.Invoice{
					p.Invoice,
				},
			}
			invoiceBytes, err := proto.Marshal(il)
			if err != nil {
				return SubmitTransactionResult{}, errors.Wrap(err, "failed to serialize invoice list")
			}
			fk = sha256.Sum224(invoiceBytes)
		}

		m, err := kin.NewMemo(1, p.Type, c.opts.appIndex, fk[:])
		if err != nil {
			return SubmitTransactionResult{}, errors.Wrap(err, "failed to create memo")
		}

		instructions = append(instructions, memo.Instruction(base64.StdEncoding.EncodeToString(m[:])))
	}

	if transferSource == nil {
		transferSource = p.Sender.Public()
	}

	instructions = append(instructions, p.createAccountInstructions...)
	instructions = append(
		instructions,
		token.Transfer(
			ed25519.PublicKey(transferSource),
			ed25519.PublicKey(p.Destination),
			ed25519.PublicKey(p.Sender.Public()),
			uint64(p.Quarks),
		),
	)

	tx := solana.NewTransaction(ed25519.PublicKey(subsidizerID), instructions...)
	return c.signAndSubmitTx(ctx, signers, tx, commitment, il, p.DedupeID)
}

func (c *client) submitEarnBatchWithResolution(ctx context.Context, batch EarnBatch, config *transactionpbv4.GetServiceConfigResponse, solanaOpts solanaOpts) (SubmitTransactionResult, error) {
	var transferSender kin.PublicKey
	result, err := c.submitSolanaEarnBatch(ctx, batch, config, solanaOpts.commitment, transferSender, solanaOpts.subsidizer)
	if err != nil {
		return result, err
	}

	if result.Errors.TxError == ErrAccountDoesNotExist {
		var resubmit bool
		if solanaOpts.accountResolution == AccountResolutionPreferred {
			tokenAccounts, err := c.internal.ResolveTokenAccounts(ctx, batch.Sender.Public(), false)
			if err != nil {
				return result, err
			}
			if len(tokenAccounts) > 0 {
				transferSender = tokenAccounts[0].AccountId.Value
				resubmit = true
			}
		}
		if solanaOpts.destResolution == AccountResolutionPreferred {
			for i, earn := range batch.Earns {
				tokenAccounts, err := c.internal.ResolveTokenAccounts(ctx, earn.Destination, false)
				if err != nil {
					return result, err
				}
				if len(tokenAccounts) > 0 {
					batch.Earns[i].Destination = tokenAccounts[0].AccountId.Value
					resubmit = true
				}
			}
		}

		if resubmit {
			result, err = c.submitSolanaEarnBatch(ctx, batch, config, solanaOpts.commitment, transferSender, solanaOpts.subsidizer)
		}
	}

	return result, err
}

func (c *client) submitSolanaEarnBatch(ctx context.Context, batch EarnBatch, config *transactionpbv4.GetServiceConfigResponse, commitment commonpbv4.Commitment, transferSender kin.PublicKey, subsidizer kin.PrivateKey) (SubmitTransactionResult, error) {
	var subsidizerID kin.PublicKey
	var signers []kin.PrivateKey
	if subsidizer != nil {
		subsidizerID = subsidizer.Public()
		signers = []kin.PrivateKey{subsidizer, batch.Sender}
	} else {
		subsidizerID = config.GetSubsidizerAccount().GetValue()
		signers = []kin.PrivateKey{batch.Sender}
	}

	var instructions []solana.Instruction
	var il *commonpb.InvoiceList

	if batch.Memo != "" {
		instructions = append(instructions, memo.Instruction(batch.Memo))
	} else if c.opts.appIndex > 0 {
		var fk [sha256.Size224]byte

		if batch.Earns[0].Invoice != nil {
			il = &commonpb.InvoiceList{
				Invoices: make([]*commonpb.Invoice, len(batch.Earns)),
			}

			for i, e := range batch.Earns {
				il.Invoices[i] = e.Invoice
			}

			invoiceBytes, err := proto.Marshal(il)
			if err != nil {
				return SubmitTransactionResult{}, errors.Wrap(err, "failed to serialize invoice list")
			}
			fk = sha256.Sum224(invoiceBytes)
		}

		m, err := kin.NewMemo(1, kin.TransactionTypeEarn, c.opts.appIndex, fk[:])
		if err != nil {
			return SubmitTransactionResult{}, errors.Wrap(err, "failed to create memo")
		}

		instructions = append(instructions, memo.Instruction(base64.StdEncoding.EncodeToString(m[:])))
	}

	if transferSender == nil {
		transferSender = batch.Sender.Public()
	}

	for _, earn := range batch.Earns {
		instructions = append(
			instructions,
			token.Transfer(
				ed25519.PublicKey(transferSender),
				ed25519.PublicKey(earn.Destination),
				ed25519.PublicKey(batch.Sender.Public()),
				uint64(earn.Quarks),
			),
		)
	}

	tx := solana.NewTransaction(ed25519.PublicKey(subsidizerID), instructions...)
	return c.signAndSubmitTx(ctx, signers, tx, commitment, il, batch.DedupeID)
}

func (c *client) signAndSubmitTx(ctx context.Context, signers []kin.PrivateKey, tx solana.Transaction, commitment commonpbv4.Commitment, il *commonpb.InvoiceList, dedupeId []byte) (SubmitTransactionResult, error) {
	var result SubmitTransactionResult
	keys := make([]ed25519.PrivateKey, len(signers))
	for i, signer := range signers {
		keys[i] = ed25519.PrivateKey(signer)
	}

	var emptySig [ed25519.SignatureSize]byte

	_, err := retry.Retry(
		func() error {
			blockhash, err := c.internal.GetRecentBlockhash(ctx)
			if err != nil {
				return err
			}

			tx.SetBlockhash(blockhash)

			err = tx.Sign(keys...)
			if err != nil {
				return err
			}

			// If the transaction isn't subsidized, request a signature.
			var remoteSigned bool
			if tx.Signatures[0] == (solana.Signature{}) {
				signResult, err := c.internal.SignTransaction(ctx, tx, il)
				if err != nil {
					return err
				}

				if len(signResult.InvoiceErrors) != 0 {
					result.InvoiceErrors = signResult.InvoiceErrors
					return nil
				}

				if bytes.Equal(signResult.ID, emptySig[:]) {
					return ErrPayerRequired
				}

				remoteSigned = true
				copy(tx.Signatures[0][:], signResult.ID)
			}

			result, err = c.internal.SubmitSolanaTransaction(ctx, tx, il, commitment, dedupeId)
			result.ID = tx.Signature()
			if err != nil {
				return err
			}

			if result.Errors.TxError == ErrBadNonce {
				// If we encounter a bad nonce, _and_ we've remote signed the transaction,
				// then we need to clear the state so the next iteration will properly
				// request a new signature (with the updated block hash)
				if remoteSigned {
					result.ID = nil
					tx.Signatures[0] = solana.Signature{}
				}

				return ErrBadNonce
			}

			return nil
		},
		retry.Limit(c.opts.maxSequenceRetries),
		retry.RetriableErrors(ErrBadNonce),
	)

	return result, err
}
