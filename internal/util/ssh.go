// Copyright 2019 Sorint.lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"
)

// GenSSHKeyPair generate an ssh keypair in rsa format, returning the private
// key (in pem encoding) and the public key (in the OpenSSH base64 format)
func GenSSHKeyPair(bits int) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	var privateBuf bytes.Buffer
	if err := pem.Encode(&privateBuf, privateKeyPEM); err != nil {
		return nil, nil, errors.New("failed to pem encode private key")
	}

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, errors.New("failed to generate public key")
	}

	// remove trailing \n returned by ssh.MarshalAuthorizedKey
	return privateBuf.Bytes(), bytes.TrimSuffix(ssh.MarshalAuthorizedKey(pub), []byte("\n")), nil
}

// ExtraxtPublicKey extracts the public key from a ssh private key in pem format
func ExtractPublicKey(privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing rsa private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse rsa private key")
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, errors.New("failed to validate rsa private key")
	}

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, errors.New("failed to generate public key")
	}

	// remove trailing \n returned by ssh.MarshalAuthorizedKey
	return bytes.TrimSuffix(ssh.MarshalAuthorizedKey(pub), []byte("\n")), nil
}
