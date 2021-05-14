package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/kinecosystem/agora-api/genproto/airdrop/v4"
	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/agora-common/solana"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	accountpbv4 "github.com/kinecosystem/agora-api/genproto/account/v4"
	airdroppbv4 "github.com/kinecosystem/agora-api/genproto/airdrop/v4"
	commonpbv4 "github.com/kinecosystem/agora-api/genproto/common/v4"
	transactionpbv4 "github.com/kinecosystem/agora-api/genproto/transaction/v4"
)

var RecentBlockhash = bytes.Repeat([]byte{1}, 32)
var MinBalanceForRentException = uint64(1234567)
var MaxAirdrop = uint64(100000)

type server struct {
	Mux    sync.Mutex
	Errors []error

	Creates       []*accountpbv4.CreateAccountRequest
	Accounts      map[string]*accountpbv4.AccountInfo
	TokenAccounts map[string][]*commonpbv4.SolanaAccountId

	ServiceConfigReqs []*transactionpbv4.GetServiceConfigRequest
	ServiceConfig     *transactionpbv4.GetServiceConfigResponse
	Subsidizer        ed25519.PrivateKey

	Gets            map[string]transactionpbv4.GetTransactionResponse
	Signs           []*transactionpbv4.SignTransactionRequest
	Submits         []*transactionpbv4.SubmitTransactionRequest
	SignResponses   []*transactionpbv4.SignTransactionResponse
	SubmitResponses []*transactionpbv4.SubmitTransactionResponse

	EventsResponses []*accountpbv4.Events
}

func newServer() *server {
	return &server{
		Accounts:      make(map[string]*accountpbv4.AccountInfo),
		TokenAccounts: make(map[string][]*commonpbv4.SolanaAccountId),
		Gets:          make(map[string]transactionpbv4.GetTransactionResponse),
	}
}

func (t *server) CreateAccount(ctx context.Context, req *accountpbv4.CreateAccountRequest) (*accountpbv4.CreateAccountResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	if err := t.GetError(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	var tx solana.Transaction
	if err := tx.Unmarshal(req.Transaction.Value); err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad transaction encoding")
	}

	t.Creates = append(t.Creates, proto.Clone(req).(*accountpbv4.CreateAccountRequest))
	parsed, err := kin.ParseTransaction(tx, nil)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid transaction")
	}
	if len(parsed.Regions) > 2 {
		return nil, status.Error(codes.InvalidArgument, "too many regions")
	}

	var tokenAccID, ownerID string
	var tokenAddr ed25519.PublicKey
	for _, r := range parsed.Regions {
		switch len(r.Creations) {
		case 0:
			continue
		case 1:
			if tokenAccID != "" {
				return nil, status.Error(codes.InvalidArgument, "too many account creations")
			}
		default:
			return nil, status.Error(codes.InvalidArgument, "too many account creations")
		}

		if r.Creations[0].Create != nil {
			tokenAddr = r.Creations[0].Create.Address
			tokenAccID = base58.Encode(tokenAddr)
			ownerID = base58.Encode(r.Creations[0].AccountHolder.NewAuthority)
		} else {
			tokenAddr = r.Creations[0].CreateAssoc.Address
			tokenAccID = base58.Encode(tokenAddr)
			ownerID = base58.Encode(r.Creations[0].CreateAssoc.Owner)
		}
	}

	if info, ok := t.Accounts[tokenAccID]; ok {
		return &accountpbv4.CreateAccountResponse{
			Result:      accountpbv4.CreateAccountResponse_EXISTS,
			AccountInfo: proto.Clone(info).(*accountpbv4.AccountInfo),
		}, nil
	}

	accountInfo := &accountpbv4.AccountInfo{
		AccountId: &commonpbv4.SolanaAccountId{Value: tokenAddr},
		Balance:   10,
	}
	t.Accounts[tokenAccID] = accountInfo
	t.TokenAccounts[ownerID] = append(t.TokenAccounts[ownerID], &commonpbv4.SolanaAccountId{Value: tokenAddr})

	return &accountpbv4.CreateAccountResponse{
		AccountInfo: accountInfo,
	}, nil
}

func (t *server) GetAccountInfo(ctx context.Context, req *accountpbv4.GetAccountInfoRequest) (*accountpbv4.GetAccountInfoResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	accountInfo, ok := t.Accounts[base58.Encode(req.AccountId.Value)]
	if !ok {
		return &accountpbv4.GetAccountInfoResponse{
			Result: accountpbv4.GetAccountInfoResponse_NOT_FOUND,
		}, nil
	}

	return &accountpbv4.GetAccountInfoResponse{
		AccountInfo: proto.Clone(accountInfo).(*accountpbv4.AccountInfo),
	}, nil
}

func (t *server) ResolveTokenAccounts(ctx context.Context, req *accountpbv4.ResolveTokenAccountsRequest) (*accountpbv4.ResolveTokenAccountsResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	ownerID := base58.Encode(req.AccountId.Value)

	accounts, ok := t.TokenAccounts[ownerID]
	if !ok {
		return &accountpbv4.ResolveTokenAccountsResponse{}, nil
	}

	resp := &accountpbv4.ResolveTokenAccountsResponse{
		TokenAccounts:     make([]*commonpbv4.SolanaAccountId, len(accounts)),
		TokenAccountInfos: make([]*accountpbv4.AccountInfo, len(accounts)),
	}

	for i, a := range accounts {
		resp.TokenAccounts[i] = proto.Clone(a).(*commonpbv4.SolanaAccountId)

		if req.IncludeAccountInfo {
			info, ok := t.Accounts[base58.Encode(a.Value)]
			if !ok {
				return nil, status.Error(codes.Internal, "account info not found")
			}

			resp.TokenAccountInfos[i] = proto.Clone(info).(*accountpbv4.AccountInfo)
		} else {
			resp.TokenAccountInfos[i] = &accountpbv4.AccountInfo{
				AccountId: proto.Clone(a).(*commonpbv4.SolanaAccountId),
			}
		}

	}

	return resp, nil
}

func (t *server) GetEvents(req *accountpbv4.GetEventsRequest, stream accountpbv4.Account_GetEventsServer) error {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := t.GetError(); err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	if _, ok := t.Accounts[base58.Encode(req.AccountId.Value)]; !ok {
		if err := stream.Send(&accountpbv4.Events{Result: accountpbv4.Events_NOT_FOUND}); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		return nil
	}

	for _, e := range t.EventsResponses {
		if err := stream.Send(e); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}

	return nil
}

func (t *server) GetServiceConfig(ctx context.Context, req *transactionpbv4.GetServiceConfigRequest) (*transactionpbv4.GetServiceConfigResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	t.ServiceConfigReqs = append(t.ServiceConfigReqs, req)
	return t.ServiceConfig, nil
}

func (t *server) GetMinimumKinVersion(ctx context.Context, req *transactionpbv4.GetMinimumKinVersionRequest) (*transactionpbv4.GetMinimumKinVersionResponse, error) {
	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	return &transactionpbv4.GetMinimumKinVersionResponse{Version: 4}, nil
}

func (t *server) GetRecentBlockhash(ctx context.Context, req *transactionpbv4.GetRecentBlockhashRequest) (*transactionpbv4.GetRecentBlockhashResponse, error) {
	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	return &transactionpbv4.GetRecentBlockhashResponse{Blockhash: &commonpbv4.Blockhash{Value: RecentBlockhash}}, nil
}

func (t *server) GetMinimumBalanceForRentExemption(ctx context.Context, req *transactionpbv4.GetMinimumBalanceForRentExemptionRequest) (*transactionpbv4.GetMinimumBalanceForRentExemptionResponse, error) {
	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	return &transactionpbv4.GetMinimumBalanceForRentExemptionResponse{Lamports: MinBalanceForRentException}, nil
}

func (t *server) GetHistory(context.Context, *transactionpbv4.GetHistoryRequest) (*transactionpbv4.GetHistoryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "")
}

func (t *server) SignTransaction(ctx context.Context, req *transactionpbv4.SignTransactionRequest) (*transactionpbv4.SignTransactionResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	if err := t.GetError(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	tx := solana.Transaction{}
	if err := tx.Unmarshal(req.Transaction.Value); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal tx: %v", err)
	}

	t.Signs = append(t.Signs, proto.Clone(req).(*transactionpbv4.SignTransactionRequest))
	if len(t.SignResponses) > 0 {
		r := t.SignResponses[0]
		t.SignResponses = t.SignResponses[1:]
		if r != nil {
			r.Signature = &commonpbv4.TransactionSignature{
				Value: tx.Signature(),
			}
			return r, nil
		}
	}

	if t.ServiceConfig != nil && t.ServiceConfig.GetSubsidizerAccount() != nil && t.Subsidizer != nil && bytes.Equal(tx.Signatures[0][:], make([]byte, ed25519.SignatureSize)) {
		err := tx.Sign(t.Subsidizer)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to sign transaction with subsidizer")
		}
	}

	return &transactionpbv4.SignTransactionResponse{
		Signature: &commonpbv4.TransactionSignature{
			Value: tx.Signature(),
		},
	}, nil
}

func (t *server) SubmitTransaction(ctx context.Context, req *transactionpbv4.SubmitTransactionRequest) (*transactionpbv4.SubmitTransactionResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	if err := t.GetError(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	tx := solana.Transaction{}
	if err := tx.Unmarshal(req.Transaction.Value); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal tx: %v", err)
	}

	t.Submits = append(t.Submits, proto.Clone(req).(*transactionpbv4.SubmitTransactionRequest))
	if len(t.SubmitResponses) > 0 {
		r := t.SubmitResponses[0]
		t.SubmitResponses = t.SubmitResponses[1:]
		if r != nil {
			r.Signature = &commonpbv4.TransactionSignature{
				Value: tx.Signature(),
			}
			return r, nil
		}
	}

	if t.ServiceConfig != nil && t.ServiceConfig.GetSubsidizerAccount() != nil && t.Subsidizer != nil && bytes.Equal(tx.Signatures[0][:], make([]byte, ed25519.SignatureSize)) {
		err := tx.Sign(t.Subsidizer)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to sign transaction with subsidizer")
		}
	}

	return &transactionpbv4.SubmitTransactionResponse{
		Signature: &commonpbv4.TransactionSignature{
			Value: tx.Signature(),
		},
	}, nil
}

func (t *server) GetTransaction(ctx context.Context, req *transactionpbv4.GetTransactionRequest) (*transactionpbv4.GetTransactionResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	if err := t.GetError(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if resp, ok := t.Gets[string(req.TransactionId.Value)]; ok {
		return &resp, nil
	}

	return &transactionpbv4.GetTransactionResponse{
		State: transactionpbv4.GetTransactionResponse_UNKNOWN,
	}, nil
}

func (t *server) RequestAirdrop(ctx context.Context, req *airdrop.RequestAirdropRequest) (*airdrop.RequestAirdropResponse, error) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	if err := validateV4Headers(ctx); err != nil {
		return nil, err
	}

	if err := t.GetError(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	_, ok := t.Accounts[base58.Encode(req.AccountId.Value)]
	if !ok {
		return &airdroppbv4.RequestAirdropResponse{Result: airdroppbv4.RequestAirdropResponse_NOT_FOUND}, nil
	}

	if req.Quarks > MaxAirdrop {
		return &airdroppbv4.RequestAirdropResponse{Result: airdroppbv4.RequestAirdropResponse_INSUFFICIENT_KIN}, nil
	}

	return &airdroppbv4.RequestAirdropResponse{
		Signature: &commonpbv4.TransactionSignature{
			Value: make([]byte, 64),
		},
	}, nil
}

func (t *server) SetError(err error, n int) {
	t.Mux.Lock()
	defer t.Mux.Unlock()

	t.Errors = make([]error, n)
	for i := 0; i < n; i++ {
		t.Errors[i] = err
	}
}

func (t *server) GetError() error {
	if len(t.Errors) == 0 {
		return nil
	}

	err := t.Errors[0]
	t.Errors = t.Errors[1:]

	return err
}

func validateV4Headers(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Internal, "failed to parse metadata")
	}

	vals := md.Get("kin-user-agent")
	for _, v := range vals {
		if strings.Contains(v, "KinSDK") {
			return nil
		}
	}

	return status.Error(codes.InvalidArgument, "missing user-agent")
}
