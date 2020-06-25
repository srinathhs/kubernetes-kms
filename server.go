// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	b64 "encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	kvmgmt "github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	k8spb "github.com/Azure/kubernetes-kms/v1beta1"
	"gocloud.dev/secrets"
	_ "gocloud.dev/secrets/localsecrets"
	"golang.org/x/net/trace"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

const (
	// Unix Domain Socket
	netProtocol      = "unix"
	socketPath       = "/var/run/kmsplugin/socketv2.sock"
	version          = "v1beta1"
	runtime          = "Microsoft AzureKMS"
	runtimeVersion   = "0.0.9"
	maxRetryTimeout  = 60
	retryIncrement   = 5
	azurePublicCloud = "AzurePublicCloud"
)

type AzureConfig struct {
	Id    string `json:"id"`
	Value string `json:"value" binding:"required"`
}

var (
	localsecret *string
)

// KeyManagementServiceServer is a gRPC server.
type KeyManagementServiceServer struct {
	*grpc.Server
	azConfig           *AzureAuthConfig
	pathToUnixSocket   string
	providerVaultName  *string
	providerKeyName    *string
	providerKeyVersion *string
	net.Listener
	configFilePath string
	env            *azure.Environment
	resourceGroup  *string
}

// New creates an instance of the KMS Service Server.
func New(pathToUnixSocketFile string, configFilePath string) (*KeyManagementServiceServer, error) {
	keyManagementServiceServer := new(KeyManagementServiceServer)
	keyManagementServiceServer.pathToUnixSocket = pathToUnixSocketFile
	keyManagementServiceServer.configFilePath = configFilePath
	azConfig, err := GetAzureAuthConfig(keyManagementServiceServer.configFilePath)
	if err != nil {
		return nil, err
	}
	keyManagementServiceServer.azConfig = azConfig
	if keyManagementServiceServer.azConfig.SubscriptionID == "" {
		return nil, fmt.Errorf("Missing SubscriptionID in azure config")
	}
	vaultName, keyName, keyVersion, resourceGroup, err := GetKMSProvider(keyManagementServiceServer.configFilePath)
	if err != nil {
		return nil, err
	}
	keyManagementServiceServer.providerVaultName = vaultName
	keyManagementServiceServer.providerKeyName = keyName
	keyManagementServiceServer.providerKeyVersion = keyVersion
	keyManagementServiceServer.resourceGroup = resourceGroup

	keyManagementServiceServer.env, err = GetCloudEnv(configFilePath)
	if err != nil {
		return nil, err
	}
	fmt.Println(keyManagementServiceServer.pathToUnixSocket)
	return keyManagementServiceServer, nil
}

func getSecret(basicClient kv.BaseClient, secname string, providerVaultName string) (*string, error) {
	secretResp, err := basicClient.GetSecret(context.Background(), "https://"+providerVaultName+".vault.azure.net", secname, "")
	if err != nil {
		fmt.Printf("unable to get value for secret: %v\n", err)
		os.Exit(1)
	}
	return secretResp.Value, nil
}

func getKey(ctx context.Context, subscriptionID string, providerVaultName string, providerKeyName string, providerKeyVersion string, resourceGroup string, configFilePath string, env *azure.Environment) (kv.BaseClient, string, string, string, error) {
	kvClient := kv.New()
	kvClient.AddToUserAgent("k8s-kms-keyvault")
	vaultUrl, _, err := getVault(ctx, subscriptionID, providerVaultName, resourceGroup, configFilePath, env)
	if err != nil {
		return kvClient, "", "", "", fmt.Errorf("failed to get vault, error: %v", err)
	}
	token, err := GetKeyvaultToken(AuthGrantType(), configFilePath)
	if err != nil {
		return kvClient, "", "", "", fmt.Errorf("failed to get token, error: %v", err)
	}

	kvClient.Authorizer = token

	fmt.Println("Verify key version from key vault ", providerKeyName, providerKeyVersion, *vaultUrl)

	var kid *string
	keyBundle, err := kvClient.GetKey(ctx, *vaultUrl, providerKeyName, providerKeyVersion)
	if err != nil {
		if providerKeyVersion != "" {
			return kvClient, "", "", "", fmt.Errorf("failed to verify the provided key version, error: %v", err)
		}
	} else {
		// when we get latest key version from api, not from config file
		if providerKeyVersion == "" {
			kid = keyBundle.Key.Kid
		}
	}
	// when we get new key id, update key version in config file
	if kid != nil {
		version, err := getVersionFromKid(kid)
		if err != nil {
			return kvClient, "", "", "", err
		}
		fmt.Println("found key version: ", version)
		// save keyversion to azure.json
		err = UpdateKMSProvider(configFilePath, version)
		if err != nil {
			return kvClient, "", "", "", err
		}
		return kvClient, *vaultUrl, providerKeyName, version, nil
	}

	return kvClient, *vaultUrl, providerKeyName, providerKeyVersion, nil
}

func getVaultsClient(subscriptionID string, configFilePath string, env *azure.Environment) kvmgmt.VaultsClient {
	vaultsClient := kvmgmt.NewVaultsClientWithBaseURI(env.ResourceManagerEndpoint, subscriptionID)
	token, _ := GetManagementToken(AuthGrantType(), configFilePath)
	vaultsClient.Authorizer = token
	return vaultsClient
}

func getVault(ctx context.Context, subscriptionID string, vaultName string, resourceGroup string, configFilePath string, env *azure.Environment) (vaultUrl *string, sku kvmgmt.SkuName, err error) {
	vaultsClient := getVaultsClient(subscriptionID, configFilePath, env)
	vault, err := vaultsClient.Get(ctx, resourceGroup, vaultName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get vault, error: %v", err)
	}

	return vault.Properties.VaultURI, vault.Properties.Sku.Name, nil
}

func getVersionFromKid(kid *string) (version string, err error) {
	if kid == nil {
		return "", fmt.Errorf("Key id is nil")
	}
	version = to.String(kid)
	index := strings.LastIndex(version, "/")
	if index > -1 && index < len(version)-1 {
		version = version[index+1:]
	}
	if version == "" {
		return "", fmt.Errorf("failed to parse version from: %v", kid)
	}
	return version, nil
}

func getKeyV2(ctx context.Context, subscriptionID string, providerVaultName string, providerKeyName string, providerKeyVersion string, resourceGroup string, configFilePath string, env *azure.Environment) (*secrets.Keeper, error) {
	if localsecret == nil {

		kvClient, vaultBaseUrl, keyName, keyVersion, err := getKey(ctx, subscriptionID, providerVaultName, providerKeyName, providerKeyVersion, resourceGroup, configFilePath, env)
		if err != nil {
			fmt.Printf("unable to get key: %v\n", err)
			os.Exit(1)
		}
		data, err := getSecret(kvClient, "EncryptionProvider", providerVaultName)
		if err != nil {
			fmt.Printf("unable to get secret: %v\n", err)
			os.Exit(1)
		}
		parameter := kv.KeyOperationsParameters{
			Algorithm: kv.RSAOAEP,
			Value:     data,
		}

		result, err := kvClient.Decrypt(ctx, vaultBaseUrl, keyName, keyVersion, parameter)
		if err != nil {
			fmt.Println("failed to decrypt, error: ", err)
			return nil, err
		}
		//fmt.Println(*result.Result)
		s := *result.Result
		if i := len(s) % 4; i != 0 {
			s += strings.Repeat("=", 4-i)
		}
		sDec, err := b64.StdEncoding.DecodeString(s)
		if err != nil {
			fmt.Println("failed to decrypt, error: ", err)
			return nil, err
		}
		kee := string(sDec)
		localsecret = &kee
	}
	// bytes, err := base64.RawURLEncoding.DecodeString(*result.Result)
	savedKeyKeeper, err := secrets.OpenKeeper(ctx, *localsecret)
	if err != nil {
		return nil, err
	}
	return savedKeyKeeper, nil

}

// doEncrypt encrypts with an existing key
func doEncrypt(ctx context.Context, data []byte, subscriptionID string, providerVaultName string, providerKeyName string, providerKeyVersion string, resourceGroup string, configFilePath string, env *azure.Environment, s *KeyManagementServiceServer) ([]byte, error) {
	keeper, err := getKeyV2(ctx, subscriptionID, providerVaultName, providerKeyName, providerKeyVersion, resourceGroup, configFilePath, env)
	defer keeper.Close()
	if err != nil {
		log.Println("doEncrypt failed")
		return nil, err
	}
	cipherText, err := keeper.Encrypt(ctx, data)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// doDecrypt decrypts with an existing key
func doDecrypt(ctx context.Context, data string, subscriptionID string, providerVaultName string, providerKeyName string, providerKeyVersion string, resourceGroup string, configFilePath string, env *azure.Environment, s *KeyManagementServiceServer) ([]byte, error) {
	keeper, err := getKeyV2(ctx, subscriptionID, providerVaultName, providerKeyName, providerKeyVersion, resourceGroup, configFilePath, env)
	defer keeper.Close()
	if err != nil {
		log.Println("doDecrypt failed")
		return nil, err
	}
	var cipherText = []byte(data)
	plainText, err := keeper.Decrypt(ctx, cipherText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func main() {
	sigChan := make(chan os.Signal, 1)
	// register for SIGTERM (docker)
	signal.Notify(sigChan, syscall.SIGTERM)

	var (
		debugListenAddr = flag.String("debug-listen-addr", "127.0.0.1:7902", "HTTP listen address.")
	)
	configFilePath := flag.String("configFilePath", "/etc/kubernetes/azure.json", "Path for Azure Cloud Provider config file. ")
	flag.Parse()

	if configFilePath == nil {
		log.Fatalf("Failed to retrieve configFilePath")
	}

	log.Println("KeyManagementServiceServer service starting...")
	s, err := New(socketPath, *configFilePath)
	if err != nil {
		log.Fatalf("Failed to start, error: %v", err)
	}
	if err := s.cleanSockFile(); err != nil {
		log.Fatalf("Failed to clean sockfile, error: %v", err)
	}

	listener, err := net.Listen(netProtocol, s.pathToUnixSocket)
	if err != nil {
		log.Fatalf("Failed to start listener, error: %v", err)
	}
	s.Listener = listener

	server := grpc.NewServer()
	k8spb.RegisterKeyManagementServiceServer(server, s)
	s.Server = server

	go server.Serve(listener)
	trace.AuthRequest = func(req *http.Request) (any, sensitive bool) { return true, true }
	log.Println("KeyManagementServiceServer service started successfully.")

	go func() {
		for {
			s := <-sigChan
			if s == syscall.SIGTERM {
				fmt.Println("force stop")
				fmt.Println("Shutting down gRPC service...")
				server.GracefulStop()
				os.Exit(0)
			}
		}
	}()

	log.Fatal(http.ListenAndServe(*debugListenAddr, nil))
}

func (s *KeyManagementServiceServer) Version(ctx context.Context, request *k8spb.VersionRequest) (*k8spb.VersionResponse, error) {
	fmt.Println(version)
	return &k8spb.VersionResponse{Version: version, RuntimeName: runtime, RuntimeVersion: runtimeVersion}, nil
}

func (s *KeyManagementServiceServer) Encrypt(ctx context.Context, request *k8spb.EncryptRequest) (*k8spb.EncryptResponse, error) {

	fmt.Println("Processing EncryptRequest: ")
	cipher, err := doEncrypt(ctx, request.Plain, s.azConfig.SubscriptionID, *(s.providerVaultName), *(s.providerKeyName), *(s.providerKeyVersion), *(s.resourceGroup), s.configFilePath, s.env, s)
	if err != nil {
		fmt.Println("failed to doencrypt, error: ", err)
		return &k8spb.EncryptResponse{}, err
	}
	return &k8spb.EncryptResponse{Cipher: cipher}, nil
}

func (s *KeyManagementServiceServer) Decrypt(ctx context.Context, request *k8spb.DecryptRequest) (*k8spb.DecryptResponse, error) {

	fmt.Println("Processing DecryptRequest: ")
	plain, err := doDecrypt(ctx, string(request.Cipher), s.azConfig.SubscriptionID, *(s.providerVaultName), *(s.providerKeyName), *(s.providerKeyVersion), *(s.resourceGroup), s.configFilePath, s.env, s)
	if err != nil {
		fmt.Println("failed to decrypt, error: ", err)
		return &k8spb.DecryptResponse{}, err
	}
	return &k8spb.DecryptResponse{Plain: plain}, nil
}

func (s *KeyManagementServiceServer) cleanSockFile() error {
	err := unix.Unlink(s.pathToUnixSocket)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete the socket file, error: %v", err)
	}
	return nil
}
