// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
