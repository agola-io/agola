// Copyright 2025 Sorint.lab
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
	"net"
	"net/url"
)

// ExpandURLPorts returns a list of urls.
// If the provided URL uses default http/https ports without a defined port of with a default port, two urls will be returned. One without the default port and one with the default port.
func ExpandURLDefaultPorts(u *url.URL) []*url.URL {
	hostname := u.Hostname()
	port := u.Port()

	// if a default port is defined add also the version without port defined
	if (u.Scheme == "http" && (port == "" || port == "80")) || (u.Scheme == "https" && (port == "" || port == "443")) {
		urls := []*url.URL{}

		// without port
		nu := new(url.URL)
		*nu = *u
		nu.Host = hostname
		urls = append(urls, nu)

		// with default port
		nu = new(url.URL)
		*nu = *u
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
		nu.Host = net.JoinHostPort(hostname, port)
		urls = append(urls, nu)

		return urls
	}

	return []*url.URL{u}
}
