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

package registry

import (
	"encoding/base64"
	"fmt"
	"strings"

	"agola.io/agola/services/runservice/types"
	errors "golang.org/x/xerrors"

	"github.com/google/go-containerregistry/pkg/name"
)

//func registryAuthToken(auth *types.DockerRegistryAuth) (string, error) {
//	if auth == nil {
//		return "", nil
//	}
//
//	switch auth.Type {
//	case types.DockerRegistryAuthTypeBasic:
//		authConfig := dtypes.AuthConfig{
//			Username: auth.Username,
//			Password: auth.Password,
//		}
//		authConfigj, err := json.Marshal(authConfig)
//		if err != nil {
//			panic(err)
//		}
//		return base64.URLEncoding.EncodeToString(authConfigj), nil
//
//	default:
//		return "", errors.Errorf("unsupported registry auth type %q", auth.Type)
//	}
//}

// Docker config represents the docker config.json format. We only consider the "auths" part
type DockerConfig struct {
	Auths map[string]DockerConfigAuth `json:"auths,omitempty"`
}

// Docker config represents the docker config.json auth part. We only consider the "auth" token part
type DockerConfigAuth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Auth     string `json:"auth,omitempty"`
}

// There are a variety of ways a domain may get qualified within the Docker credential file.
// We enumerate them here as format strings.
var (
	domainForms = []string{
		// Allow naked domains
		"%s",
		// Allow scheme-prefixed.
		"https://%s",
		"http://%s",
		// Allow scheme-prefixes with version in url path.
		"https://%s/v1/",
		"http://%s/v1/",
		"https://%s/v2/",
		"http://%s/v2/",
	}
)

func GetRegistry(image string) (string, error) {
	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return "", err
	}
	regName := ref.Context().RegistryStr()
	return regName, nil
}

// ResolveAuth resolves the auth username and password for the provided registry name
func ResolveAuth(auths map[string]types.DockerRegistryAuth, regname string) (string, string, error) {
	if auths != nil {
		for _, form := range domainForms {
			if auth, ok := auths[fmt.Sprintf(form, regname)]; ok {
				switch auth.Type {
				case types.DockerRegistryAuthTypeEncodedAuth:
					decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
					if err != nil {
						return "", "", errors.Errorf("failed to decode docker auth: %w", err)
					}
					parts := strings.Split(string(decoded), ":")
					if len(parts) != 2 {
						return "", "", errors.Errorf("wrong docker auth: %w", err)
					}
					return parts[0], parts[1], nil
				case types.DockerRegistryAuthTypeBasic:
					return auth.Username, auth.Password, nil
				default:
					return "", "", fmt.Errorf("unsupported auth type %q", auth.Type)
				}
			}
		}
	}

	return "", "", nil
}

func GenDockerConfig(auths map[string]types.DockerRegistryAuth, images []string) (*DockerConfig, error) {
	dockerConfig := &DockerConfig{Auths: make(map[string]DockerConfigAuth)}
	for _, image := range images {
		ref, err := name.ParseReference(image, name.WeakValidation)
		if err != nil {
			return nil, err
		}
		regName := ref.Context().RegistryStr()

		if _, ok := dockerConfig.Auths[regName]; ok {
			continue
		}

		username, password, err := ResolveAuth(auths, regName)
		if err != nil {
			return nil, errors.Errorf("failed to resolve auth: %w", err)
		}
		delimited := fmt.Sprintf("%s:%s", username, password)
		auth := base64.StdEncoding.EncodeToString([]byte(delimited))
		dockerConfig.Auths[regName] = DockerConfigAuth{Username: username, Password: password, Auth: auth}
	}

	return dockerConfig, nil
}
