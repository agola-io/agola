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

package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"path"
	"regexp"
	"strings"
	"unicode"

	gitsave "agola.io/agola/internal/git-save"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/ghodss/yaml"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdDirectRunStart = &cobra.Command{
	Use: "start",
	Run: func(cmd *cobra.Command, args []string) {
		if err := directRunStart(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "executes a run from a local git repository",
}

type directRunStartOptions struct {
	untracked bool
	ignored   bool

	branch       string
	tag          string
	ref          string
	prRefRegexes []string

	vars     []string
	varFiles []string
}

var directRunStartOpts directRunStartOptions

func init() {
	flags := cmdDirectRunStart.Flags()

	flags.BoolVar(&directRunStartOpts.untracked, "untracked", true, "push untracked files")
	flags.BoolVar(&directRunStartOpts.ignored, "ignored", false, "push ignored files")
	flags.StringVar(&directRunStartOpts.branch, "branch", "master", "branch to push to")
	flags.StringVar(&directRunStartOpts.tag, "tag", "", "tag to push to")
	flags.StringVar(&directRunStartOpts.ref, "ref", "", `ref to push to (i.e  "refs/heads/master" for a branch, "refs/tags/v1.0" for a tag)`)
	flags.StringArrayVar(&directRunStartOpts.prRefRegexes, "pull-request-ref-regexes", []string{`refs/pull/(\d+)/head`, `refs/merge-requests/(\d+)/head`}, `regular expression to determine if a ref is a pull request`)
	flags.StringArrayVar(&directRunStartOpts.vars, "var", []string{}, `list of variables (name=value). This option can be repeated multiple times`)
	flags.StringArrayVar(&directRunStartOpts.varFiles, "var-file", []string{}, `yaml file containing the variables as a yaml/json map. This option can be repeated multiple times`)

	cmdDirectRun.AddCommand(cmdDirectRunStart)
}

func parseVariable(variable string) (string, string, error) {
	// trim white spaces at the start
	variable = strings.TrimLeftFunc(variable, unicode.IsSpace)
	arr := strings.SplitN(variable, "=", 2)
	if len(arr) != 2 {
		return "", "", fmt.Errorf("invalid variable definition: %s", variable)
	}
	varname := arr[0]
	varvalue := arr[1]
	if varname == "" {
		return "", "", fmt.Errorf("invalid variable definition: %s", variable)
	}
	if varvalue == "" {
		return "", "", fmt.Errorf("invalid variable definition: %s", variable)
	}
	return varname, varvalue, nil
}

func directRunStart(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	for _, res := range directRunStartOpts.prRefRegexes {
		if _, err := regexp.Compile(res); err != nil {
			return fmt.Errorf("wrong regular expression %q: %v", res, err)
		}
	}

	branch := directRunStartOpts.branch
	tag := directRunStartOpts.tag
	ref := directRunStartOpts.ref

	set := 0

	flags := cmd.Flags()
	if flags.Changed("branch") {
		set++
	}
	if tag != "" {
		set++
		// unset branch default value
		branch = ""
	}
	if ref != "" {
		set++
		// unset branch default value
		branch = ""
	}
	if set > 1 {
		return fmt.Errorf(`only one of "--branch", "--tag" or "--ref" can be provided`)
	}

	user, _, err := gwclient.GetCurrentUser(context.TODO())
	if err != nil {
		return err
	}

	variables := map[string]string{}

	// TODO(sgotti) currently vars overrides varFiles. Is this what we want or we
	// want to handle var and varFiles in the order they appear in the command
	// line?
	for _, varFile := range directRunStartOpts.varFiles {
		// "github.com/ghodss/yaml" doesn't provide a streaming decoder
		var data []byte
		var err error
		data, err = ioutil.ReadFile(varFile)
		if err != nil {
			return err
		}

		if err := yaml.Unmarshal(data, &variables); err != nil {
			return errors.Errorf("failed to unmarshal values: %v", err)
		}

		// TODO(sgotti) validate variable name
	}

	for _, variable := range directRunStartOpts.vars {
		varname, varvalue, err := parseVariable(variable)
		if err != nil {
			return err
		}
		variables[varname] = varvalue
	}

	// setup unique local git repo uuid
	git := &util.Git{}
	repoUUID, _ := git.ConfigGet(context.Background(), "agola.repouuid")
	if repoUUID == "" {
		repoUUID = uuid.NewV4().String()
		if _, err := git.ConfigSet(context.Background(), "agola.repouuid", repoUUID); err != nil {
			return fmt.Errorf("failed to set agola repo uid in git config: %v", err)
		}
	}

	gs := gitsave.NewGitSave(logger, &gitsave.GitSaveConfig{
		AddUntracked: directRunStartOpts.untracked,
		AddIgnored:   directRunStartOpts.ignored,
	})

	localBranch := "gitsavebranch-" + uuid.NewV4().String()
	message := "agola direct run"

	commitSHA, err := gs.Save(message, localBranch)
	if err != nil {
		return err
	}

	log.Infof("pushing branch")
	repoPath := fmt.Sprintf("%s/%s", user.ID, repoUUID)
	repoURL := fmt.Sprintf("%s/repos/%s/%s.git", gatewayURL, user.ID, repoUUID)

	// push to a branch with default branch refs "refs/heads/branch"
	if branch != "" {
		if err := gitsave.GitPush("", repoURL, fmt.Sprintf("%s:refs/heads/%s", path.Join(gs.RefsPrefix(), localBranch), branch)); err != nil {
			return err
		}
	} else if tag != "" {
		if err := gitsave.GitPush("", repoURL, fmt.Sprintf("%s:refs/tags/%s", path.Join(gs.RefsPrefix(), localBranch), tag)); err != nil {
			return err
		}
	} else if ref != "" {
		if err := gitsave.GitPush("", repoURL, fmt.Sprintf("%s:%s", path.Join(gs.RefsPrefix(), localBranch), ref)); err != nil {
			return err
		}
	}

	log.Infof("starting direct run")
	req := &gwapitypes.UserCreateRunRequest{
		RepoUUID:              repoUUID,
		RepoPath:              repoPath,
		Branch:                branch,
		Tag:                   tag,
		Ref:                   ref,
		CommitSHA:             commitSHA,
		Message:               message,
		PullRequestRefRegexes: directRunStartOpts.prRefRegexes,
		Variables:             variables,
	}
	if _, err := gwclient.UserCreateRun(context.TODO(), req); err != nil {
		return err
	}

	return nil
}
