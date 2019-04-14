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

package cmd

import (
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"text/template"
	"time"

	"github.com/spf13/cobra"
)

var cmdTemplate = &cobra.Command{
	Use:   "template",
	Run:   templateRun,
	Short: "executes the provided template from stdin and returns the output in stdout",
}

func init() {
	CmdToolbox.AddCommand(cmdTemplate)
}

func md5sum(filename string) (string, error) {
	if filename == "" {
		return "", errors.New("empty filename")
	}

	if info, err := os.Stat(filename); err == nil {
		if info.Size() > 1024*1024 {
			return "", fmt.Errorf("file %q is too big", filename)
		}
	} else {
		return "", err
	}

	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func sha256sum(filename string) (string, error) {
	if filename == "" {
		return "", errors.New("empty filename")
	}

	if info, err := os.Stat(filename); err == nil {
		if info.Size() > 1024*1024 {
			return "", fmt.Errorf("file %q is too big", filename)
		}
	} else {
		return "", err
	}

	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

type tmplData struct {
	Environment map[string]string
}

func templateRun(cmd *cobra.Command, args []string) {

	funcMap := map[string]interface{}{
		"md5sum":    md5sum,
		"sha256sum": sha256sum,
		"env":       func(s string) string { return os.Getenv(s) },
		"os":        func() string { return runtime.GOOS },
		"arch":      func() string { return runtime.GOARCH },
		"unixtime":  func() string { return strconv.FormatInt(time.Now().UnixNano(), 10) },
		"year":      func() string { return time.Now().Format("2006") },
		"month":     func() string { return time.Now().Format("01") },
		"day":       func() string { return time.Now().Format("02") },
	}

	tmplStr, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read template: %v", err)
	}

	tmpl, err := template.New("base").Funcs(funcMap).Parse(string(tmplStr))
	if err != nil {
		log.Fatalf("failed to parse template: %v", err)
	}

	data := &tmplData{}
	if err := tmpl.Execute(os.Stdout, data); err != nil {
		log.Fatalf("failed to execute template: %v", err)
	}
}
