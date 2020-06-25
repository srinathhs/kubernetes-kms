// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	k8spb "github.com/Azure/kubernetes-kms/v1beta1"
)

var (
	client *KeyManagementServiceServer
)

const cred = `
{
    "tenantId": "648bdd45-afd6-44d5-9ef0-e45d3904c4b6",
    "subscriptionId": "a9867c6d-8d28-4335-b478-8f61e11f5454",
    "aadClientId": "c6864a6b-a418-4caa-acf0-c6b714930d95",
    "aadClientSecret": "asdfgdfgretg",
    "resourceGroup": "kubernetes",
    "location": "south-india",
    "providerVaultName": "bb-k8s-stg",
    "providerKeyName": "rsa-hsm-primary",
    "providerKeyVersion": "f26dc6b643794f52a84b8556a73cf33b"
}`

func setupTestCase(t *testing.T) func(t *testing.T) {
	t.Log("setup test case")
	file, err := ioutil.TempFile("", "kms_test")
	if err != nil {
		t.Error(err)
	}

	if _, err := file.Write([]byte(cred)); err != nil {
		t.Error(err)
	}

	client = new(KeyManagementServiceServer)
	client.pathToUnixSocket = "/tmp/azurekms.socket"
	client.configFilePath = file.Name()
	azConfig, err := GetAzureAuthConfig(client.configFilePath)
	if err != nil {
		t.Error(err)
	}
	client.azConfig = azConfig
	if client.azConfig.SubscriptionID == "" {
		t.Error(fmt.Errorf("Missing SubscriptionID in azure config"))
	}
	vaultName, keyName, keyVersion, resourceGroup, err := GetKMSProvider(client.configFilePath)
	if err != nil {
		t.Error(err)
	}
	client.providerVaultName = vaultName
	client.providerKeyName = keyName
	client.providerKeyVersion = keyVersion
	client.resourceGroup = resourceGroup

	client.env, err = GetCloudEnv(file.Name())
	if err != nil {
		t.Error(err)
	}
	fmt.Println(client.pathToUnixSocket)

	return func(t *testing.T) {
		t.Log("teardown test case")
		os.Remove(file.Name())
	}
}

func TestEncryptDecrypt(t *testing.T) {
	cases := []struct {
		name     string
		want     []byte
		expected []byte
	}{
		{"text", []byte("secret"), []byte("secret")},
		{"number", []byte("1234"), []byte("1234")},
		{"special", []byte("!@#$%^&*()_"), []byte("!@#$%^&*()_")},
		{"GUID", []byte("b32a58c6-48c1-4552-8ff0-47680f3416d0"), []byte("b32a58c6-48c1-4552-8ff0-47680f3416d0")},
	}

	cases1 := []struct {
		name     string
		want     string
		expected string
	}{
		{"v1beta1", "v1beta1", "v1beta1"},
	}

	teardownTestCase := setupTestCase(t)
	defer teardownTestCase(t)
	for _, tc := range cases1 {
		t.Run(tc.name, func(t *testing.T) {

			request := &k8spb.VersionRequest{Version: tc.want}
			response, err := client.Version(context.Background(), request)
			if err != nil {
				t.Fatalf("failed get version from remote KMS provider: %v", err)
			}
			if response.Version != tc.want {
				t.Fatalf("KMS provider api version %s is not supported, only %s is supported now", tc.want, version)
			}
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			encryptRequest := k8spb.EncryptRequest{Version: version, Plain: tc.want}
			encryptResponse, err := client.Encrypt(context.Background(), &encryptRequest)

			decryptRequest := k8spb.DecryptRequest{Version: version, Cipher: encryptResponse.Cipher}
			decryptResponse, err := client.Decrypt(context.Background(), &decryptRequest)
			if string(decryptResponse.Plain) != string(tc.want) {
				t.Fatalf("Expected secret, but got %s - %v", string(decryptResponse.Plain), err)
			}
		})
	}
}

func TestCreateInstance(t *testing.T) {
	file, err := ioutil.TempFile("", "kms_test")
	if err != nil {
		t.Error(err)
	}

	defer os.Remove(file.Name())

	if _, err := file.Write([]byte(cred)); err != nil {
		t.Error(err)
	}

	cred, err := GetAzureAuthConfig(file.Name())
	if err != nil {
		t.Error(err)
	}

	KVTestName, KVTestKeyName, KVTestVersion, RGTest, err := GetKMSProvider(file.Name())
	if err != nil {
		t.Error(err)
	}

	keyManagementServiceServer := new(KeyManagementServiceServer)
	keyManagementServiceServer.pathToUnixSocket = "/tmp/azurekms.socket"
	keyManagementServiceServer.azConfig = cred
	keyManagementServiceServer.providerVaultName = KVTestName
	keyManagementServiceServer.providerKeyName = KVTestKeyName
	keyManagementServiceServer.providerKeyVersion = KVTestVersion

	wanted := "72f988bf-86f1-41af-91ab-2d7cd011db47"
	if cred.TenantID != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, cred.TenantID)
	}

	wanted = "11122233-4444-5555-6666-777888999000"
	if cred.SubscriptionID != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, cred.SubscriptionID)
	}

	wanted = "123"
	if cred.AADClientID != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, cred.AADClientID)
	}

	wanted = "456"
	if cred.AADClientSecret != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, cred.AADClientSecret)
	}

	wanted = "mykeyvaultrg"
	if *RGTest != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, *RGTest)
	}

	wanted = "k8skv"
	if *keyManagementServiceServer.providerVaultName != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, *keyManagementServiceServer.providerVaultName)
	}

	wanted = "mykey"
	if *keyManagementServiceServer.providerKeyName != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, *keyManagementServiceServer.providerKeyName)
	}

	wanted = "bd497c644699475d9fb22dbbc15ba286"
	if *keyManagementServiceServer.providerKeyVersion != wanted {
		t.Errorf("Wanted %s, got %s.", wanted, *keyManagementServiceServer.providerKeyVersion)
	}
}

func TestCreateInstanceNoCredentials(t *testing.T) {
	file, err := ioutil.TempFile("", "kms_test")
	if err != nil {
		t.Error(err)
	}

	fileName := file.Name()

	if err := file.Close(); err != nil {
		t.Error(err)
	}

	os.Remove(fileName)

	if _, err := GetAzureAuthConfig(file.Name()); err == nil {
		t.Fatal("expected to fail with bad json")
	}
}

const badCred = `
{
    "tenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "subscriptionId": "11122233-4444-5555-6666-777888999000",
    "aadClientId": "123",
    "aadClientSecret": "456",
    "resourceGroup": "mykeyvaultrg",
    "location": "eastus",
    "providerVaultName": "k8skv",
	"providerKeyName": "mykey",
	"providerKeyVersion": "bd497c644699475d9fb22dbbc15ba286",`

func TestCreateInstanceBadCredentials(t *testing.T) {
	file, err := ioutil.TempFile("", "kms_test")
	if err != nil {
		t.Error(err)
	}

	defer os.Remove(file.Name())

	if _, err := file.Write([]byte(badCred)); err != nil {
		t.Error(err)
	}

	if _, err := GetAzureAuthConfig(file.Name()); err == nil {
		t.Fatal("expected to fail with bad json")
	}

}
