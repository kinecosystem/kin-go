package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"net/http"
	"os"

	"github.com/kinecosystem/agora-common/kin"
	"github.com/kinecosystem/kin-go/client"
)

var whitelistKey kin.PrivateKey

func createHandler(req client.CreateAccountRequest, resp *client.CreateAccountResponse) error {
	return resp.Sign(whitelistKey)
}

// signHandler blindly whitelists every transaction that's directed to it.
//
// The handler rejects any transaction where a sender is the same as the
// whitelist account, to avoid callers from stealing kin from said account.
func signHandler(req client.SignTransactionRequest, resp *client.SignTransactionResponse) error {
	for _, p := range req.Payments {
		if bytes.Equal(p.Sender, whitelistKey.Public()) {
			log.Println("rejecting whitelist request; sender was whitelist account")
			resp.Reject()
			return nil
		}
	}

	txID, err := req.TxID()
	if err != nil {
		return err
	}

	log.Println("whitelisting transaction:", hex.EncodeToString(txID))
	return resp.Sign(whitelistKey)
}

func main() {
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	if webhookSecret == "" {
		log.Fatal("missing webhook secret")
	}

	var err error
	whitelistSeed := os.Getenv("WHITELIST_SEED")
	whitelistKey, err = kin.PrivateKeyFromString(whitelistSeed)
	if err != nil {
		log.Fatal("invalid whitelist seed")
	}

	env := client.Environment(os.Getenv("ENVIRONMENT"))
	switch env {
	case client.EnvironmentTest, client.EnvironmentProd:
	default:
		log.Fatalf("unknown environment: %s", env)
	}

	http.HandleFunc("/create_account", client.CreateAccountHandler(webhookSecret, createHandler))
	http.HandleFunc("/sign_transaction", client.SignTransactionHandler(env, webhookSecret, signHandler))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
