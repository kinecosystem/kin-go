package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/agora-common/kin/version"
	"github.com/kinecosystem/agora-common/retry"
	"github.com/kinecosystem/agora-common/solana"
	"github.com/kinecosystem/agora-common/solana/memo"
	"github.com/kinecosystem/agora-common/solana/token"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	accountpbv4 "github.com/kinecosystem/agora-api/genproto/account/v4"
	airdroppbv4 "github.com/kinecosystem/agora-api/genproto/airdrop/v4"
	commonpb "github.com/kinecosystem/agora-api/genproto/common/v3"
	commonpbv4 "github.com/kinecosystem/agora-api/genproto/common/v4"
	transactionpbv4 "github.com/kinecosystem/agora-api/genproto/transaction/v4"
)

const (
	SDKVersion      = "0.6.0"
	userAgentHeader = "kin-user-agent"
)

var (
	userAgent = fmt.Sprintf("KinSDK/%s %s (%s; %s)", SDKVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
)

// InternalClient is a low level client used for interacting with
// Agora directly. The API is _not_ stable and is not intend for general use.
//
// It is exposed in case there needs to be low level access to Agora (beyond
// the gRPC client directly). However, there are no stability guarantees between
// releases, or during a migration event.
type InternalClient struct {
	retrier retry.Retrier

	accountClientV4     accountpbv4.AccountClient
	transactionClientV4 transactionpbv4.TransactionClient
	airdropClientV4     airdroppbv4.AirdropClient

	configMux         sync.Mutex
	serviceConfig     *transactionpbv4.GetServiceConfigResponse
	configLastFetched time.Time
}

func NewInternalClient(cc *grpc.ClientConn, retrier retry.Retrier) *InternalClient {
	return &InternalClient{
		retrier:             retrier,
		accountClientV4:     accountpbv4.NewAccountClient(cc),
		transactionClientV4: transactionpbv4.NewTransactionClient(cc),
		airdropClientV4:     airdroppbv4.NewAirdropClient(cc),
	}
}

func (c *InternalClient) GetBlockchainVersion(ctx context.Context) (version.KinVersion, error) {
	ctx = c.addMetadataToCtx(ctx)

	var kinVersion version.KinVersion
	_, err := c.retrier.Retry(
		func() error {
			resp, err := c.transactionClientV4.GetMinimumKinVersion(ctx, &transactionpbv4.GetMinimumKinVersionRequest{})
			if err != nil {
				return err
			}

			kinVersion = version.KinVersion(resp.Version)
			return nil
		},
	)
	if err != nil {
		return version.KinVersionUnknown, err
	}
	return kinVersion, nil
}

type SignTransactionResult struct {
	ID            []byte
	InvoiceErrors []*commonpb.InvoiceError
}

type SubmitTransactionResult struct {
	ID            []byte
	Errors        TransactionErrors
	InvoiceErrors []*commonpb.InvoiceError
}

func (s SubmitTransactionResult) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ID: %s\n", base58.Encode(s.ID)))
	sb.WriteString("Errors:\n")
	sb.WriteString(fmt.Sprintf("\tTxError: %v\n", s.Errors.TxError))
	sb.WriteString("\tOpErrors:\n")
	for i, o := range s.Errors.OpErrors {
		sb.WriteString(fmt.Sprintf("\t\t%d: %v\n", i, o))
	}
	sb.WriteString("\tPaymentErrors:\n")
	for i, o := range s.Errors.PaymentErrors {
		sb.WriteString(fmt.Sprintf("\t\t%d: %v\n", i, o))
	}
	sb.WriteString("\tInvoiceErrors:\n")
	for i, o := range s.InvoiceErrors {
		sb.WriteString(fmt.Sprintf("\t\t%d: %v\n", i, o))
	}

	return sb.String()
}

func (c *InternalClient) CreateSolanaAccount(ctx context.Context, key kin.PrivateKey, commitment commonpbv4.Commitment, subsidizer kin.PrivateKey, appIndex uint16) (err error) {
	ctx = c.addMetadataToCtx(ctx)

	config, err := c.GetServiceConfig(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get service config")
	}

	if subsidizer == nil && config.GetSubsidizerAccount().GetValue() == nil {
		return ErrNoSubsidizer
	}

	owner := ed25519.PublicKey(key.Public())

	var subsidizerID ed25519.PublicKey
	if len(subsidizer) != 0 {
		subsidizerID = ed25519.PublicKey(subsidizer.Public())
	} else {
		subsidizerID = config.SubsidizerAccount.Value
	}

	var instructions []solana.Instruction
	if appIndex > 0 {
		m, err := kin.NewMemo(1, kin.TransactionTypeNone, appIndex, nil)
		if err != nil {
			return errors.Wrap(err, "failed to create memo")
		}

		instructions = append(instructions, memo.Instruction(base64.StdEncoding.EncodeToString(m[:])))
	}

	createInstruction, addr, err := token.CreateAssociatedTokenAccount(
		subsidizerID,
		owner,
		config.Token.Value,
	)
	if err != nil {
		return errors.Wrap(err, "failed to generate associated token account instruction")
	}

	instructions = append(instructions, createInstruction)
	instructions = append(instructions, token.SetAuthority(
		addr,
		owner,
		subsidizerID,
		token.AuthorityTypeCloseAccount,
	))

	tx := solana.NewTransaction(
		subsidizerID,
		instructions...,
	)

	recentBlockhash, err := c.GetRecentBlockhash(ctx)
	if err != nil {
		return err
	}
	tx.SetBlockhash(recentBlockhash)

	var signers []ed25519.PrivateKey
	if subsidizer != nil {
		signers = []ed25519.PrivateKey{ed25519.PrivateKey(subsidizer), ed25519.PrivateKey(key)}
	} else {
		signers = []ed25519.PrivateKey{ed25519.PrivateKey(key)}
	}
	err = tx.Sign(signers...)
	if err != nil {
		return errors.Wrap(err, "failed to sign transaction")
	}

	var resp *accountpbv4.CreateAccountResponse
	_, err = c.retrier.Retry(func() error {
		resp, err = c.accountClientV4.CreateAccount(ctx, &accountpbv4.CreateAccountRequest{
			Transaction: &commonpbv4.Transaction{
				Value: tx.Marshal(),
			},
			Commitment: commitment,
		})

		return err
	})
	if err != nil {
		return errors.Wrap(err, "failed to create account")
	}

	switch resp.Result {
	case accountpbv4.CreateAccountResponse_OK:
		return nil
	case accountpbv4.CreateAccountResponse_EXISTS:
		return ErrAccountExists
	case accountpbv4.CreateAccountResponse_PAYER_REQUIRED:
		return ErrPayerRequired
	case accountpbv4.CreateAccountResponse_BAD_NONCE:
		return ErrBadNonce
	default:
		return errors.Errorf("unexpected result from agora: %v", resp.Result)
	}
}

func (c *InternalClient) GetSolanaAccountInfo(ctx context.Context, account kin.PublicKey, commitment commonpbv4.Commitment) (accountInfo *accountpbv4.AccountInfo, err error) {
	ctx = c.addMetadataToCtx(ctx)

	_, err = c.retrier.Retry(func() error {
		resp, err := c.accountClientV4.GetAccountInfo(ctx, &accountpbv4.GetAccountInfoRequest{
			AccountId:  &commonpbv4.SolanaAccountId{Value: account},
			Commitment: commitment,
		})
		if err != nil {
			return err
		}

		switch resp.Result {
		case accountpbv4.GetAccountInfoResponse_OK:
			accountInfo = resp.AccountInfo
			return nil
		case accountpbv4.GetAccountInfoResponse_NOT_FOUND:
			return ErrAccountDoesNotExist
		default:
			return errors.Errorf("unexpected result from agora: %v", resp.Result)
		}
	})

	if err != nil {
		return nil, err
	}

	return accountInfo, nil
}

func (c *InternalClient) GetEvents(ctx context.Context, account kin.PublicKey) (<-chan EventsResult, error) {
	var ch chan EventsResult
	_, err := c.retrier.Retry(func() error {
		stream, err := c.accountClientV4.GetEvents(ctx, &accountpbv4.GetEventsRequest{AccountId: &commonpbv4.SolanaAccountId{Value: account}})
		if err != nil {
			return err
		}

		ch = make(chan EventsResult)
		go func() {
			defer close(ch)
			for {
				resp, err := stream.Recv()
				if err != nil {
					ch <- EventsResult{
						Err: err,
					}
					return
				}

				switch resp.GetResult() {
				case accountpbv4.Events_NOT_FOUND:
					ch <- EventsResult{
						Err: ErrAccountDoesNotExist,
					}
					return
				default:
				}

				ch <- EventsResult{
					Events: resp.GetEvents(),
				}
			}
		}()

		return nil
	})

	return ch, err
}

func (c *InternalClient) ResolveTokenAccounts(ctx context.Context, publicKey kin.PublicKey, includeAccountInfo bool) (accounts []*accountpbv4.AccountInfo, err error) {
	ctx = c.addMetadataToCtx(ctx)

	var resp *accountpbv4.ResolveTokenAccountsResponse

	_, err = c.retrier.Retry(func() error {
		resp, err = c.accountClientV4.ResolveTokenAccounts(ctx, &accountpbv4.ResolveTokenAccountsRequest{
			AccountId:          &commonpbv4.SolanaAccountId{Value: publicKey},
			IncludeAccountInfo: includeAccountInfo,
		})
		return err
	})
	if err != nil {
		return accounts, errors.Wrap(err, "failed to resolve token accounts")
	}

	// This is currently in place for backward compat with the server.
	if len(resp.TokenAccountInfos) != len(resp.TokenAccounts) {
		// If we aren't requesting account info, we can interpolate the results ourselves.
		if !includeAccountInfo {
			resp.TokenAccountInfos = make([]*accountpbv4.AccountInfo, len(resp.TokenAccounts))
			for i := 0; i < len(resp.TokenAccounts); i++ {
				resp.TokenAccountInfos[i] = &accountpbv4.AccountInfo{
					AccountId: resp.TokenAccounts[i],
				}
			}
		} else {
			return nil, errors.New("server does not support resolving with account info")
		}
	}

	return resp.TokenAccountInfos, nil
}

func (c *InternalClient) GetTransaction(ctx context.Context, txID []byte, commitment commonpbv4.Commitment) (data TransactionData, err error) {
	ctx = c.addMetadataToCtx(ctx)

	var resp *transactionpbv4.GetTransactionResponse

	_, err = c.retrier.Retry(func() error {
		resp, err = c.transactionClientV4.GetTransaction(ctx, &transactionpbv4.GetTransactionRequest{
			TransactionId: &commonpbv4.TransactionId{
				Value: txID,
			},
			Commitment: commitment,
		})
		return err
	})
	if err != nil {
		return TransactionData{}, errors.Wrap(err, "failed to get transaction")
	}

	data.TxID = txID
	data.TxState = txStateFromProto(resp.State)
	if resp.Item != nil {
		data.Payments, data.Errors, err = parseHistoryItem(resp.Item)
		if err != nil {
			return TransactionData{}, errors.Wrap(err, "failed to parse payments")
		}
	}

	return data, nil
}

func (c *InternalClient) SignTransaction(ctx context.Context, tx solana.Transaction, il *commonpb.InvoiceList) (result SignTransactionResult, err error) {
	ctx = c.addMetadataToCtx(ctx)

	var resp *transactionpbv4.SignTransactionResponse
	_, err = c.retrier.Retry(func() error {
		resp, err = c.transactionClientV4.SignTransaction(ctx, &transactionpbv4.SignTransactionRequest{
			Transaction: &commonpbv4.Transaction{Value: tx.Marshal()},
			InvoiceList: il,
		})

		return err
	})
	if err != nil {
		return result, err
	}

	if len(resp.Signature.GetValue()) == ed25519.SignatureSize {
		result.ID = resp.Signature.Value
	}

	switch resp.Result {
	case transactionpbv4.SignTransactionResponse_OK:
	case transactionpbv4.SignTransactionResponse_REJECTED:
		return result, ErrTransactionRejected
	case transactionpbv4.SignTransactionResponse_INVOICE_ERROR:
		result.InvoiceErrors = resp.InvoiceErrors
	default:
		return result, errors.Errorf("unexpected result from agora: %v", resp.Result)
	}

	return result, nil
}

func (c *InternalClient) SubmitSolanaTransaction(ctx context.Context, tx solana.Transaction, il *commonpb.InvoiceList, commitment commonpbv4.Commitment, dedupeID []byte) (result SubmitTransactionResult, err error) {
	ctx = c.addMetadataToCtx(ctx)

	attempt := 0

	var resp *transactionpbv4.SubmitTransactionResponse

	_, err = c.retrier.Retry(func() error {
		attempt += 1

		resp, err = c.transactionClientV4.SubmitTransaction(ctx, &transactionpbv4.SubmitTransactionRequest{
			Transaction: &commonpbv4.Transaction{Value: tx.Marshal()},
			InvoiceList: il,
			Commitment:  commitment,
			DedupeId:    dedupeID,
		})
		if err != nil {
			return errors.Wrap(err, "failed to submit transaction")
		}

		if resp.Result == transactionpbv4.SubmitTransactionResponse_ALREADY_SUBMITTED && attempt == 1 {
			return ErrAlreadySubmitted
		}

		return nil
	})
	if err != nil {
		return result, err
	}

	result.ID = resp.Signature.GetValue()

	switch resp.Result {
	case transactionpbv4.SubmitTransactionResponse_OK:
	case transactionpbv4.SubmitTransactionResponse_ALREADY_SUBMITTED:
	case transactionpbv4.SubmitTransactionResponse_REJECTED:
		return result, ErrTransactionRejected
	case transactionpbv4.SubmitTransactionResponse_PAYER_REQUIRED:
		return result, ErrPayerRequired
	case transactionpbv4.SubmitTransactionResponse_FAILED:
		txErrors := errorsFromSolanaTx(&tx, resp.TransactionError)
		result.Errors = txErrors
	case transactionpbv4.SubmitTransactionResponse_INVOICE_ERROR:
		result.InvoiceErrors = resp.InvoiceErrors
	default:
		return result, errors.Errorf("unexpected result from agora: %v", resp.Result)
	}

	return result, nil
}

func (c *InternalClient) GetServiceConfig(ctx context.Context) (resp *transactionpbv4.GetServiceConfigResponse, err error) {
	ctx = c.addMetadataToCtx(ctx)

	c.configMux.Lock()
	resp = c.serviceConfig
	lastFetched := c.configLastFetched
	c.configMux.Unlock()

	if resp != nil && time.Since(lastFetched) < time.Hour*24 {
		return resp, nil
	}

	_, err = c.retrier.Retry(func() error {
		resp, err = c.transactionClientV4.GetServiceConfig(ctx, &transactionpbv4.GetServiceConfigRequest{})
		return err
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get service config")
	}

	c.configMux.Lock()
	c.serviceConfig = resp
	c.configLastFetched = time.Now()
	c.configMux.Unlock()

	return resp, nil
}

func (c *InternalClient) GetRecentBlockhash(ctx context.Context) (blockhash solana.Blockhash, err error) {
	ctx = c.addMetadataToCtx(ctx)

	var resp *transactionpbv4.GetRecentBlockhashResponse

	_, err = c.retrier.Retry(func() error {
		resp, err = c.transactionClientV4.GetRecentBlockhash(ctx, &transactionpbv4.GetRecentBlockhashRequest{})
		return err
	})
	if err != nil {
		return blockhash, errors.Wrap(err, "failed to get recent blockhash")
	}

	copy(blockhash[:], resp.Blockhash.Value)
	return blockhash, nil
}

func (c *InternalClient) GetMinimumBalanceForRentException(ctx context.Context, size uint64) (balance uint64, err error) {
	ctx = c.addMetadataToCtx(ctx)

	var resp *transactionpbv4.GetMinimumBalanceForRentExemptionResponse

	_, err = c.retrier.Retry(func() error {
		resp, err = c.transactionClientV4.GetMinimumBalanceForRentExemption(ctx,
			&transactionpbv4.GetMinimumBalanceForRentExemptionRequest{
				Size: size,
			})
		return err
	})
	if err != nil {
		return balance, errors.Wrap(err, "failed to get minimum balance for rent exception")
	}

	return resp.Lamports, nil
}

func (c *InternalClient) RequestAirdrop(ctx context.Context, publicKey kin.PublicKey, quarks uint64, commitment commonpbv4.Commitment) (txID []byte, err error) {
	ctx = c.addMetadataToCtx(ctx)

	var resp *airdroppbv4.RequestAirdropResponse

	_, err = c.retrier.Retry(func() error {
		resp, err = c.airdropClientV4.RequestAirdrop(ctx, &airdroppbv4.RequestAirdropRequest{
			AccountId:  &commonpbv4.SolanaAccountId{Value: publicKey},
			Quarks:     quarks,
			Commitment: commitment,
		})
		return err
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to request airdrop")
	}

	switch resp.Result {
	case airdroppbv4.RequestAirdropResponse_OK:
		return resp.Signature.Value, nil
	case airdroppbv4.RequestAirdropResponse_NOT_FOUND:
		return nil, ErrAccountDoesNotExist
	case airdroppbv4.RequestAirdropResponse_INSUFFICIENT_KIN:
		return nil, ErrInsufficientBalance
	default:
		return nil, errors.Errorf("unexpected result from agora: %v", resp.Result)
	}
}

func (c *InternalClient) addMetadataToCtx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(
		ctx,
		userAgentHeader, userAgent,
		version.KinVersionHeader, strconv.Itoa(int(version.KinVersion4)),
	)
}
