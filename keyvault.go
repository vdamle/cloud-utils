package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	b64 "encoding/base64"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/json"
)

type azureKeyVaultConfig struct {
	ClientID        string `json:"clientId"`
	ClientSecret    string `json:"clientSecret"`
	TenantID        string `json:"tenantId"`
	KeyVaultName    string `json:"keyVaultName"`
	KeyVaultBaseURL string `json:"keyVaultBaseUrl"`
	KeyID           string `json:"keyId"`
	KeyName         string `json:"keyName"`
}

// AddressBook maintains entries of key names, ethereum public address and public key that can be used to recover address from signature
type AddressBook struct {
	keyName       string
	commonAddress string
	publicKey     []byte
}

var (
	log            = logrus.New()
	configFilePath = "/Users/vdamle/go/src/github.com/vdamle/cloud-utils/config.json"
	ctx            = context.Background()
	testPayload    = "blueSky"
	addressBook    = []AddressBook{}
)

func getResource() (*string, error) {
	envName := os.Getenv("AZURE_ENVIRONMENT")
	var env azure.Environment
	var err error

	if envName == "" {
		env = azure.PublicCloud
	} else {
		env, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return nil, err
		}
	}

	resource := os.Getenv("AZURE_KEYVAULT_RESOURCE")
	if resource == "" {
		resource = strings.TrimSuffix(env.KeyVaultEndpoint, "/")
	}

	return &resource, nil
}

func createClient(conf *azureKeyVaultConfig) (*autorest.Authorizer, *keyvault.BaseClient, error) {
	resource, _ := getResource()
	log.Infof("Resource (%s)", *resource)
	authorizer, err := auth.NewAuthorizerFromFileWithResource(*resource)
	if err != nil {
		log.Errorf("Unable to authorize client credentials %v", err)
		return nil, nil, err
	}
	baseClient := keyvault.New()
	baseClient.Authorizer = authorizer
	return &authorizer, &baseClient, nil
}

func createAddressBookEntry(keyName string, publicKeyX []byte, publicKeyY []byte) *AddressBook {
	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = crypto.S256()
	publicKey.X = new(big.Int)
	publicKey.X.SetBytes(publicKeyX)
	publicKey.Y = new(big.Int)
	publicKey.Y.SetBytes(publicKeyY)
	addr := crypto.PubkeyToAddress(*publicKey)
	addressBookEntry := new(AddressBook)
	addressBookEntry.keyName = keyName
	addressBookEntry.publicKey = crypto.FromECDSAPub(publicKey)
	addressBookEntry.commonAddress = addr.String()
	return addressBookEntry
}

func getKeys(conf *azureKeyVaultConfig, azureClient *keyvault.BaseClient) {
	log.Infof("Get keys from %s", conf.KeyVaultBaseURL)
	keys, err := azureClient.GetKeys(ctx, conf.KeyVaultBaseURL, nil)
	if err != nil {
		log.Errorf("Unable to fetch keys from keyVault (%s):(%s)", conf.KeyVaultBaseURL, err)
	}
	values := keys.Values()
	// log.Infof("Got keys from with length %d", len(values))
	for i := 0; i < len(values); i++ {
		keyID := *values[i].Kid
		urlPaths := strings.Split(keyID, "/")
		keyName := urlPaths[len(urlPaths)-1]
		bundle, err := azureClient.GetKey(ctx, conf.KeyVaultBaseURL, keyName, "")
		if err != nil {
			log.Errorf("Unable to fetch key from keyVault (%s):(%s)", keyName, err)
		}
		key := *bundle.Key
		if !(key.Kty == "EC" && key.Crv == "P-256K") {
			log.Warnf("Skipping key with index:(%d), name:(%s), type: (%+v)", i, keyName, key)
			continue
		}

		bigX, err := b64.RawURLEncoding.DecodeString(*key.X)
		if err != nil {
			log.Errorf("Unable to decode keyX", err)
		}
		bigY, err := b64.RawURLEncoding.DecodeString(*key.Y)
		if err != nil {
			log.Errorf("Unable to decode keyY", err)
		}
		entry := createAddressBookEntry(keyName, bigX, bigY)
		addressBook = append(addressBook, *entry)
	}
}

func readConfig() (*azureKeyVaultConfig, error) {
	var kvConfig azureKeyVaultConfig
	f, err := os.Open(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open config file '%s': %s", configFilePath, err)
	}
	defer f.Close()
	input := bufio.NewReader(f)

	if err = json.NewDecoder(input).Decode(&kvConfig); err != nil {
		return nil, fmt.Errorf("Failed to read configuration: %s", err)
	}
	return &kvConfig, nil
}

func createKeys(conf *azureKeyVaultConfig, azureClient *keyvault.BaseClient) {
	// hack by using the same
	for i := 10; i < 15; i++ {
		keyName := "key-" + strconv.Itoa(i)
		log.Infof("Creating key:(%s) in keyvault (%s)", keyName, conf.KeyVaultBaseURL)
		params := &keyvault.KeyCreateParameters{}
		params.Kty = "EC"
		params.Curve = "P-256K"
		_, err := azureClient.CreateKey(ctx, conf.KeyVaultBaseURL, keyName, *params)
		if err != nil {
			log.Errorf("Unable to Create key in keyVault (%s):(%s)", conf.KeyVaultBaseURL, err)
		}
	}
}

func verifySignature(results []keyvault.KeyOperationResult) {
	log.Infof("\n\nAttempting to recover signer address from signed payload..")
	// we want to recover the `r` and `s` values from the signature
	testHashedPayload := crypto.Keccak256Hash([]byte(testPayload))
	// these markers will be used to extract pieces from the signature returned by the hsm
	rStart, rEnd, sStart, sEnd, vStart := 0, 32, 32, 64, 64
	for i, result := range results {
		hsmSignatureBytes, err := b64.RawURLEncoding.DecodeString(*result.Result)
		if err != nil {
			log.Errorf("Unable to convert hsm signature to bytes (%s)", err)
		}
		rBytes := hsmSignatureBytes[rStart:rEnd]
		sBytes := hsmSignatureBytes[sStart:sEnd]
		entry := addressBook[i]
		for j := 0; j < 4; j++ {
			v := j + 27
			sig := make([]byte, 65)
			copy(sig[rStart:rEnd], rBytes)
			copy(sig[sStart:sEnd], sBytes)
			sig[vStart] = byte(v)
			recovered, err := crypto.Ecrecover(testHashedPayload.Bytes(), sig)
			if err != nil {
				log.Warnf("Unable to recover signature from v:(%d):(%s)", v, err)
			}
			if bytes.Compare(recovered, entry.publicKey) == 0 {
				log.Infof("Success!! Recovered publicKey address from signature (%s)", entry.commonAddress)
			}
		}
	}
}

func signWithSDK(conf *azureKeyVaultConfig, azureClient *keyvault.BaseClient) (results []keyvault.KeyOperationResult) {
	// create a hash of the payload
	testEncodedPayload := crypto.Keccak256Hash([]byte(testPayload))
	// Azure sign API expects a base-64 URL encoded string
	testEncodedPayloadString := b64.RawURLEncoding.EncodeToString(testEncodedPayload.Bytes())

	log.Infof("Size of encoded payload:(%d), size of string converted payload:(%d)", len(testEncodedPayload), len(testEncodedPayloadString))
	for _, entry := range addressBook {
		signParameters := new(keyvault.KeySignParameters)
		signParameters.Algorithm = keyvault.ES256K
		signParameters.Value = &testEncodedPayloadString
		result, err := azureClient.Sign(ctx, conf.KeyVaultBaseURL, entry.keyName, "", *signParameters)
		if err != nil {
			log.Errorf("Unable to sign transaction for (%s):(%s), error: %s", entry.keyName, entry.commonAddress, err)
			continue
		}
		log.Infof("Signed transaction with key (%s), result (%s)", *result.Kid, *result.Result)
		results = append(results, result)
	}
	return results
}

// TODO - does not work, needs testing/fixes
func signWithURL(conf *azureKeyVaultConfig, authorizer *autorest.Authorizer, azureClient *keyvault.BaseClient) {
	// create a hash of the payload
	testEncodedPayload := crypto.Keccak256Hash([]byte(testPayload))
	// Azure sign API expects a base-64 URL encoded string
	testEncodedPayloadString := b64.RawURLEncoding.EncodeToString(testEncodedPayload.Bytes())
	testHashedPayload := crypto.Keccak256Hash([]byte(testPayload))
	for i := 0; i < len(addressBook); i++ {
		entry := addressBook[i]
		signParameters := new(keyvault.KeySignParameters)
		signParameters.Algorithm = keyvault.ES256K
		signParameters.Value = &testEncodedPayloadString
		result, err := azureClient.Sign(ctx, conf.KeyVaultBaseURL, entry.keyName, "", *signParameters)
		if err != nil {
			log.Errorf("Unable to sign transaction for (%s):(%s), error: %s", entry.keyName, entry.commonAddress, err)
			continue
		}
		log.Infof("Signed transaction with key (%s), result (%s)", *result.Kid, *result.Result)
		log.Infof("Attempting to recover signer address from signed payload..")

		signerAddress, err := crypto.Ecrecover(testHashedPayload.Bytes(), []byte(*result.Result))
		if err != nil {
			log.Errorf("Unable to recover signed transaction for (%s):(%s), error: %s", entry.keyName, entry.commonAddress, err)
			continue
		}
		log.Infof("Signer address recovered from signature: (%s), public address obtained from key (%s)", string(signerAddress), string(entry.publicKey))
	}
}

func main() {
	log.Info("Hello azure")
	var kvConfig *azureKeyVaultConfig
	var err error

	kvConfig, err = readConfig()
	if err != nil {
		log.Error("Unable to parse config")
		os.Exit(1)
	}
	_, baseClient, err := createClient(kvConfig)
	if err != nil {
		log.Error("Unable to create client")
		os.Exit(1)
	}

	// Ran this as a one time exercise to create a few keys of type P-256K
	// createKeys(kvConfig, baseClient)

	getKeys(kvConfig, baseClient)
	log.Infof("Retrieved keys from keyvault")
	for i := 0; i < len(addressBook); i++ {
		entry := addressBook[i]
		log.Infof("Keyname:(%s), Address:(%s)", entry.keyName, entry.commonAddress)
	}

	// sign payload using API in SDK - does not work if the key was created in Azure portal
	// due to https://github.com/Azure/azure-sdk-for-go/issues/7363
	// Hence created some keys using API to be able to test sign/verify
	results := signWithSDK(kvConfig, baseClient)
	verifySignature(results)
}
