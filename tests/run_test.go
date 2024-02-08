package tests

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
	rstypes "agola.io/agola/services/runservice/types"
)

func TestPush(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      string
		num         int
		annotations map[string]string
		message     string
	}{
		{
			name: "push",
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								steps: [
									{ type: 'clone' },
									{ type: 'run', command: 'env' },
								],
							},
						],
					},
				],
			}
			`,
			num: 1,
			annotations: map[string]string{
				"branch":   "master",
				"ref":      "refs/heads/master",
				"ref_type": "branch",
			},
			message: "commit",
		},
		{
			name: "push with unmatched branch",
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								steps: [
									{ type: 'clone' },
									{ type: 'run', command: 'env' },
								],
							},
						],
						when: {
							branch: 'notmaster',
						},
					},
				],
			}
			`,
			num:     0,
			message: "commit",
		},
		{
			name: "push with [ci skip] in subject",
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								steps: [
									{ type: 'clone' },
									{ type: 'run', command: 'env' },
								],
							},
						],
					},
				],
			}
			`,
			num:     0,
			message: "[ci skip] commit",
		},
		{
			name: "push with [ci skip] in body",
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								steps: [
									{ type: 'clone' },
									{ type: 'run', command: 'env' },
								],
							},
						],
					},
				],
			}
			`,
			num:     0,
			message: "commit\n\n[ci skip] body",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			testutil.NilError(t, err)

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			push(t, tt.config, giteaRepo.CloneURL, giteaToken, tt.message, false)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) == 0 {
					return false, nil
				}
				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(runs, tt.num))

			if len(runs) > 0 {
				run := runs[0]
				assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
				assert.Equal(t, run.Result, rstypes.RunResultSuccess)
				for k, v := range tt.annotations {
					assert.Equal(t, run.Annotations[k], v)
				}
			}
		})
	}
}

func TestDirectRun(t *testing.T) {
	testDirectRun(t, true)
}

func TestDirectRunWithoutInternalServicesAuth(t *testing.T) {
	testDirectRun(t, false)
}

func testDirectRun(t *testing.T, internalServicesAuth bool) {
	t.Parallel()

	config := `
	{
		runs: [
			{
				name: 'run01',
				tasks: [
					{
						name: 'task01',
						runtime: {
							containers: [
								{
									image: 'alpine/git',
								},
							],
						},
						steps: [
							{ type: 'clone' },
							{ type: 'run', command: 'env' },
						],
					},
				],
			},
		],
	}
	`

	tests := []struct {
		name        string
		args        []string
		annotations map[string]string
	}{
		{
			name: "direct run",
			annotations: map[string]string{
				"branch":   "master",
				"ref":      "refs/heads/master",
				"ref_type": "branch",
			},
		},
		{
			name: "direct run with destination branch",
			args: []string{"--branch", "develop"},
			annotations: map[string]string{
				"branch":   "develop",
				"ref":      "refs/heads/develop",
				"ref_type": "branch",
			},
		},
		{
			name: "direct run with destination tag",
			args: []string{"--tag", "v0.1.0"},
			annotations: map[string]string{
				"tag":      "v0.1.0",
				"ref":      "refs/tags/v0.1.0",
				"ref_type": "tag",
			},
		},
		{
			name: "direct run with destination ref as a pr",
			args: []string{"--ref", "refs/pull/1/head"},
			annotations: map[string]string{
				"pull_request_id": "1",
				"ref":             "refs/pull/1/head",
				"ref_type":        "pull_request",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true), withInternalServicesAuth(internalServicesAuth))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			testutil.NilError(t, err)

			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token, tt.args...)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) != 1 {
					return false, nil
				}

				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(runs, 1))

			run := runs[0]
			assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
			assert.Equal(t, run.Result, rstypes.RunResultSuccess)

			for k, v := range tt.annotations {
				assert.Equal(t, run.Annotations[k], v)
			}
		})
	}
}

func TestDirectRunVariables(t *testing.T) {
	t.Parallel()

	config := `
	{
		runs: [
			{
				name: 'run01',
				tasks: [
					{
						name: 'task01',
						runtime: {
							containers: [
								{
									image: 'alpine/git',
								},
							],
						},
						environment: {
							ENV01: { from_variable: 'variable01' },
							ENV02: { from_variable: 'variable02' },
						},
						steps: [
							{ type: 'clone' },
							{ type: 'run', command: 'env' },
						],
					},
				],
			},
		],
	}
	`

	varfile01 := `
variable01: "variable value 01"
variable02: variable value 02
`

	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{
			name: "direct run without variables",
			args: []string{},
			env: map[string]string{
				"ENV01": "",
				"ENV02": "",
			},
		},
		{
			name: "direct run with two variables",
			args: []string{"--var", "variable01=VARIABLEVALUE01", "--var", "variable02=VARIABLEVALUE02"},
			env: map[string]string{
				"ENV01": "VARIABLEVALUE01",
				"ENV02": "VARIABLEVALUE02",
			},
		},
		{
			name: "direct run with a var file",
			args: []string{"--var-file", "../varfile01.yml"},
			env: map[string]string{
				"ENV01": "variable value 01",
				"ENV02": "variable value 02",
			},
		},
		{
			name: "direct run with a var file and a var that overrides",
			args: []string{"--var-file", "../varfile01.yml", "--var", "variable02=VARIABLEVALUE02"},
			env: map[string]string{
				"ENV01": "variable value 01",
				"ENV02": "VARIABLEVALUE02",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			err := os.WriteFile(filepath.Join(dir, "varfile01.yml"), []byte(varfile01), 0644)
			testutil.NilError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			testutil.NilError(t, err)

			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token, tt.args...)

			// TODO(sgotti) add an util to wait for a run phase
			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) != 1 {
					return false, nil
				}

				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(runs, 1))

			run, _, err := gwClient.GetUserRun(ctx, user.ID, runs[0].Number)
			testutil.NilError(t, err)

			assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
			assert.Equal(t, run.Result, rstypes.RunResultSuccess)

			var task *gwapitypes.RunResponseTask
			for _, t := range run.Tasks {
				if t.Name == "task01" {
					task = t
					break
				}
			}

			resp, err := gwClient.GetUserLogs(ctx, user.ID, run.Number, task.ID, false, 1, false)
			testutil.NilError(t, err)

			defer resp.Body.Close()

			logs, err := io.ReadAll(resp.Body)
			testutil.NilError(t, err)

			curEnv, err := testutil.ParseEnvs(bytes.NewReader(logs))
			testutil.NilError(t, err)

			for n, e := range tt.env {
				ce, ok := curEnv[n]
				assert.Assert(t, ok, "missing env var %s", n)
				assert.Equal(t, ce, e, "different env var %s value, want: %q, got %q", n, e, ce)
			}
		})
	}
}

func TestDirectRunLogs(t *testing.T) {
	t.Parallel()

	config := `
	{
		runs: [
			{
				name: 'run01',
				tasks: [
					{
						name: 'task01',
						runtime: {
							containers: [
								{
									image: 'alpine/git',
								},
							],
						},
						steps: [
							{ type: 'clone' },
							{ type: 'run', command: 'echo STEPLOG' },
						],
					},
				],
			},
		],
	}
	`

	tests := []struct {
		name   string
		setup  bool
		step   int
		delete bool
		err    string
	}{
		{
			name: "get log step 1",
			step: 1,
		},
		{
			name:  "get log setup",
			setup: true,
		},
		{
			name: "get log with unexisting step",
			step: 99,
			err:  "remote error notexist",
		},
		{
			name:   "delete log step 1",
			step:   1,
			delete: true,
		},
		{
			name:   "delete log setup",
			setup:  true,
			delete: true,
		},
		{
			name:   "delete log with unexisting step",
			step:   99,
			delete: true,
			err:    "remote error notexist",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			testutil.NilError(t, err)

			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) != 1 {
					return false, nil
				}

				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(runs, 1))

			run, _, err := gwClient.GetUserRun(ctx, user.ID, runs[0].Number)
			testutil.NilError(t, err)

			assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
			assert.Equal(t, run.Result, rstypes.RunResultSuccess)

			var task *gwapitypes.RunResponseTask
			for _, t := range run.Tasks {
				if t.Name == "task01" {
					task = t
					break
				}
			}

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				t, _, err := gwClient.GetUserRunTask(ctx, user.ID, runs[0].Number, task.ID)
				if err != nil {
					return false, nil
				}
				if tt.step >= len(t.Steps) {
					return true, nil
				}
				if !t.Steps[tt.step].LogArchived {
					return false, nil
				}
				return true, nil
			})

			if tt.delete {
				_, err = gwClient.DeleteUserLogs(ctx, user.ID, run.Number, task.ID, tt.setup, tt.step)
			} else {
				_, err = gwClient.GetUserLogs(ctx, user.ID, run.Number, task.ID, tt.setup, tt.step, false)
			}

			if tt.err != "" {
				assert.Error(t, err, tt.err)
			} else {
				testutil.NilError(t, err)
			}
		})
	}
}

func TestPullRequest(t *testing.T) {
	t.Parallel()

	config := `
	{
		runs: [
			{
				name: 'run01',
				tasks: [
					{
						name: 'task01',
						runtime: {
							containers: [
								{
									image: 'alpine/git',
								},
							],
						},
						environment: {
							MYPASSWORD: { from_variable: 'mypassword' },
						},
						steps: [
							{ type: 'clone' },
							{ type: 'run', command: 'echo -n $MYPASSWORD' },
						],
					},
				],
				when: {
					ref: '#refs/pull/\\d+/head#',
				},
			},
		],
	}
	`

	tests := []struct {
		name               string
		passVarsToForkedPR bool
		prFromSameRepo     bool
		expected           string
	}{
		{
			name:               "PR from same repo with PassVarsToForkedPR set to false",
			passVarsToForkedPR: false,
			prFromSameRepo:     true,
			expected:           "mysupersecretpassword",
		},
		{
			name:               "PR from same repo with PassVarsToForkedPR set to true",
			passVarsToForkedPR: true,
			prFromSameRepo:     true,
			expected:           "mysupersecretpassword",
		},
		{
			name:               "PR from forked repo with PassVarsToForkedPR set to false",
			passVarsToForkedPR: false,
			prFromSameRepo:     false,
			expected:           "",
		},
		{
			name:               "PR from forked repo with PassVarsToForkedPR set to true",
			passVarsToForkedPR: true,
			prFromSameRepo:     false,
			expected:           "mysupersecretpassword",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			testutil.NilError(t, err)

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			project, _, err = gwClient.UpdateProject(ctx, project.ID, &gwapitypes.UpdateProjectRequest{PassVarsToForkedPR: util.BoolP(tt.passVarsToForkedPR)})
			testutil.NilError(t, err, "failed to update project")

			//create project secret
			secretData := map[string]string{"mypassword": "mysupersecretpassword"}
			sreq := &gwapitypes.CreateSecretRequest{
				Name: "mysecret",
				Type: gwapitypes.SecretTypeInternal,
				Data: secretData,
			}

			secret, _, err := gwClient.CreateProjectSecret(context.TODO(), project.ID, sreq)
			testutil.NilError(t, err, "failed to create project secret")

			// create project variable
			rvalues := []gwapitypes.VariableValueRequest{}
			rvalues = append(rvalues, gwapitypes.VariableValueRequest{
				SecretName: secret.Name,
				SecretVar:  "mypassword",
			})

			vreq := &gwapitypes.CreateVariableRequest{
				Name:   "mypassword",
				Values: rvalues,
			}

			_, _, err = gwClient.CreateProjectVariable(context.TODO(), project.ID, vreq)
			testutil.NilError(t, err, "failed to create project variable")

			if tt.prFromSameRepo {
				// create PR from branch on same repo
				push(t, config, giteaRepo.CloneURL, giteaToken, "commit", true)

				// Looks like there're some async handlings in gitea when pushing and then instantly creating a pull request that could fail with a 404 Not found
				// We tried with a wait, before pr creation, to check that the branch exists but this always returns true also if the pr creation then fails.
				// So retry the creation for some time on 404

				prOpts := gitea.CreatePullRequestOption{
					Head:  "new-branch",
					Base:  "master",
					Title: "add file1 from new-branch on same repo",
				}

				err := testutil.Wait(10*time.Second, func() (bool, error) {
					_, resp, err := giteaClient.CreatePullRequest(giteaUser01, "repo01", prOpts)
					if err != nil {
						if resp.StatusCode == http.StatusNotFound {
							return false, nil
						}
						return false, errors.WithStack(err)
					}

					return true, nil
				})
				testutil.NilError(t, err, "failed to create pull request")
			} else {
				// create PR from forked repo
				push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

				userOpts := gitea.CreateUserOption{
					Username:           giteaUser02,
					Password:           giteaUser02Password,
					Email:              "user02@example.com",
					MustChangePassword: util.BoolP(false),
				}
				_, _, err := giteaClient.AdminCreateUser(userOpts)
				testutil.NilError(t, err, "failed to create user02")

				giteaClient.SetBasicAuth(giteaUser02, giteaUser02Password)
				giteaUser02Token, _, err := giteaClient.CreateAccessToken(gitea.CreateAccessTokenOption{Name: "token01"})
				testutil.NilError(t, err, "failed to create token for user02")

				giteaUser02Client, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaUser02Token.Token))
				testutil.NilError(t, err)

				giteaForkedRepo, _, err := giteaUser02Client.CreateFork(giteaUser01, "repo01", gitea.CreateForkOption{})
				testutil.NilError(t, err, "failed to fork repo01")

				gitfs := memfs.New()
				r, err := git.Clone(memory.NewStorage(), gitfs, &git.CloneOptions{
					Auth: &githttp.BasicAuth{
						Username: giteaUser02,
						Password: giteaUser02Token.Token,
					},
					URL: giteaForkedRepo.CloneURL,
				})
				testutil.NilError(t, err, "failed to clone forked repo")

				wt, err := r.Worktree()
				testutil.NilError(t, err)

				f, err := gitfs.Create("file2")
				testutil.NilError(t, err)
				_, err = f.Write([]byte("file2 content"))
				testutil.NilError(t, err)

				_, err = wt.Add("file2")
				testutil.NilError(t, err)

				_, err = wt.Commit("commit from user02", &git.CommitOptions{
					Author: &object.Signature{
						Name:  giteaUser02,
						Email: "user02@example.com",
						When:  time.Now(),
					},
				})
				testutil.NilError(t, err)

				err = r.Push(&git.PushOptions{
					RemoteName: "origin",
					RefSpecs: []gitconfig.RefSpec{
						gitconfig.RefSpec("refs/heads/master:refs/heads/master"),
					},
					Auth: &githttp.BasicAuth{
						Username: giteaUser02,
						Password: giteaUser02Token.Token,
					},
				})
				testutil.NilError(t, err)

				prOpts := gitea.CreatePullRequestOption{
					Head:  "user02:master",
					Base:  "master",
					Title: "add file1 from master on forked repo",
				}
				_, _, err = giteaUser02Client.CreatePullRequest(giteaUser01, "repo01", prOpts)
				testutil.NilError(t, err, "failed to create pull request")
			}
			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) == 0 {
					return false, nil
				}
				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			run, _, err := gwClient.GetProjectRun(ctx, project.ID, runs[0].Number)
			testutil.NilError(t, err)

			var task *gwapitypes.RunResponseTask
			for _, t := range run.Tasks {
				if t.Name == "task01" {
					task = t
					break
				}
			}

			if len(runs) > 0 {
				run := runs[0]
				assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
				assert.Equal(t, run.Result, rstypes.RunResultSuccess)

				resp, err := gwClient.GetProjectLogs(ctx, project.ID, run.Number, task.ID, false, 1, false)
				testutil.NilError(t, err, "failed to get log")
				defer resp.Body.Close()

				mypassword, err := io.ReadAll(resp.Body)
				testutil.NilError(t, err, "failed to read log: %v")
				assert.Equal(t, tt.expected, string(mypassword))
			}
		})
	}
}

func TestTaskTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		config               string
		tasksResultExpected  map[string]rstypes.RunTaskStatus
		taskTimedoutExpected map[string]bool
	}{
		{
			name:                 "timeout string value",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed},
			taskTimedoutExpected: map[string]bool{"task01": true},
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								task_timeout_interval: "15s",
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
						],
					},
				],
			}
		`,
		},
		{
			name:                 "timeout int value",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed},
			taskTimedoutExpected: map[string]bool{"task01": true},
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								task_timeout_interval: 15000000000,
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
						],
					},
				],
			}
		`,
		},
		{
			name:                 "timeout child timeout",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusSuccess, "task02": rstypes.RunTaskStatusFailed},
			taskTimedoutExpected: map[string]bool{"task01": false, "task02": true},
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
							{
								name: 'task02',
								depends: ['task01'],
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								task_timeout_interval: "15s",
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
						],
					},
				],
			}
		`,
		},
		{
			name:                 "timeout parent timeout",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed, "task02": rstypes.RunTaskStatusSkipped},
			taskTimedoutExpected: map[string]bool{"task01": true, "task02": false},
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								task_timeout_interval: "15s",
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
							{
								name: 'task02',
								depends: ['task01'],
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
						],
					},
				],
			}
		`,
		},
		{
			name:                 "timeout parent and child timeout",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed, "task02": rstypes.RunTaskStatusSkipped},
			taskTimedoutExpected: map[string]bool{"task01": true, "task02": false},
			config: `
			{
				runs: [
					{
						name: 'run01',
						tasks: [
							{
								name: 'task01',
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								task_timeout_interval: "15s",
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
							{
								name: 'task02',
								depends: ['task01'],
								runtime: {
									containers: [
										{
											image: 'alpine/git',
										},
									],
								},
								task_timeout_interval: "15s",
								steps: [
									{ type: 'run', command: 'sleep 30' },
								],
							},
						],
					},
				],
			}
		`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			testutil.NilError(t, err)

			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, tt.config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token)

			_ = testutil.Wait(120*time.Second, func() (bool, error) {
				run, _, err := gwClient.GetUserRun(ctx, user.ID, 1)
				if err != nil {
					return false, nil
				}

				if run == nil {
					return false, nil
				}

				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			run, _, err := gwClient.GetUserRun(ctx, user.ID, 1)
			testutil.NilError(t, err)

			assert.Assert(t, run != nil)
			assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
			assert.Equal(t, run.Result, rstypes.RunResultFailed)
			assert.Assert(t, cmp.Len(run.Tasks, len(tt.tasksResultExpected)))
			for _, task := range run.Tasks {
				assert.Equal(t, task.Status, tt.tasksResultExpected[task.Name])
				assert.Equal(t, task.Timedout, tt.taskTimedoutExpected[task.Name])
			}
		})
	}
}

func TestRunRequiredEnvVariables(t *testing.T) {
	t.Parallel()

	config := `
	{
		runs: [
			{
				name: 'run01',
				tasks: [
					{
						name: 'task01',
						runtime: {
							containers: [
								{
									image: 'alpine/git',
								},
							],
						},
						steps: [
							{ type: 'run', command: 'env -u AGOLA_SSHPRIVKEY' },
						],
					},
				],
			},
		],
	}
	`

	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "push with run count 1",
			env: map[string]string{
				"AGOLA_GIT_REF_TYPE": "branch",
				"AGOLA_GIT_REF":      "refs/heads/master",
				"AGOLA_GIT_BRANCH":   "master",
				"AGOLA_GIT_TAG":      "",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)
			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			testutil.NilError(t, err)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient, withVisibility(gwapitypes.VisibilityPrivate))

			push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

			// TODO(sgotti) add an util to wait for a run phase
			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) != 1 {
					return false, nil
				}

				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(runs, 1))

			run, _, err := gwClient.GetProjectRun(ctx, project.ID, runs[0].Number)
			testutil.NilError(t, err)

			assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
			assert.Equal(t, run.Result, rstypes.RunResultSuccess)

			// update commit sha from annotations since it will change at every test
			tt.env["AGOLA_GIT_COMMITSHA"] = run.Annotations["commit_sha"]

			tt.env["AGOLA_RUN_COUNTER"] = strconv.FormatUint(run.Number, 10)

			var task *gwapitypes.RunResponseTask
			for _, t := range run.Tasks {
				if t.Name == "task01" {
					task = t
					break
				}
			}

			resp, err := gwClient.GetProjectLogs(ctx, project.ID, run.Number, task.ID, false, 0, false)
			testutil.NilError(t, err)

			defer resp.Body.Close()

			logs, err := io.ReadAll(resp.Body)
			testutil.NilError(t, err)

			curEnv, err := testutil.ParseEnvs(bytes.NewReader(logs))
			testutil.NilError(t, err)

			for n, e := range tt.env {
				ce, ok := curEnv[n]
				assert.Assert(t, ok, "missing env var %s", n)
				assert.Equal(t, ce, e, "different env var %s value, want: %q, got %q", n, e, ce)
			}
		})
	}
}

func TestConfigContext(t *testing.T) {
	t.Parallel()

	jsonnetConfig := `
function(ctx) {
	runs: [
		{
			name: 'run01',
			tasks: [
				{
					name: 'task01',
					runtime: {
						containers: [
							{
								image: 'alpine/git',
							},
						],
					},
					environment: {
						REF_TYPE: ctx.ref_type,
						REF: ctx.ref,
						BRANCH: ctx.branch,
						TAG: ctx.tag,
						PULL_REQUEST_ID: ctx.pull_request_id,
						COMMIT_SHA: ctx.commit_sha,
					},
					steps: [
						{ type: 'clone' },
						{ type: 'run', command: 'env' },
					],
				},
			],
		},
	],
}
`

	starlarkConfig := `
def main(ctx):
	return {
		"runs": [
			{
			"name": 'run01',
			"tasks": [
				{
					"name": 'task01',
					"runtime": {
						"containers": [
							{
								"image": 'alpine/git',
							}
						]
					},
					"environment": {
						"REF_TYPE": ctx["ref_type"],
						"REF": ctx["ref"],
						"BRANCH": ctx["branch"],
						"TAG": ctx["tag"],
						"PULL_REQUEST_ID": ctx["pull_request_id"],
						"COMMIT_SHA": ctx["commit_sha"]
					},
					"steps": [
						{ "type": 'clone' },
						{ "type": 'run', "command": 'env' }
					],
				},
			],
		},
	]
}
`

	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{
			name: "direct run branch",
			env: map[string]string{
				"REF_TYPE":        "branch",
				"REF":             "refs/heads/master",
				"BRANCH":          "master",
				"TAG":             "",
				"PULL_REQUEST_ID": "",
				"COMMIT_SHA":      "",
			},
		},
		{
			name: "direct run tag",
			args: []string{"--tag", "v0.1.0"},
			env: map[string]string{
				"REF_TYPE":        "tag",
				"REF":             "refs/tags/v0.1.0",
				"BRANCH":          "",
				"TAG":             "v0.1.0",
				"PULL_REQUEST_ID": "",
				"COMMIT_SHA":      "",
			},
		},
		{
			name: "direct run with pr",
			args: []string{"--ref", "refs/pull/1/head"},
			env: map[string]string{
				"REF_TYPE":        "pull_request",
				"REF":             "refs/pull/1/head",
				"BRANCH":          "",
				"TAG":             "",
				"PULL_REQUEST_ID": "1",
				"COMMIT_SHA":      "",
			},
		},
	}

	for _, configFormat := range []ConfigFormat{ConfigFormatJsonnet, ConfigFormatStarlark} {
		configFormat := configFormat
		for _, tt := range tests {
			tt := tt
			t.Run(fmt.Sprintf("%s with %s config", tt.name, configFormat), func(t *testing.T) {
				t.Parallel()

				var config string
				switch configFormat {
				case ConfigFormatJsonnet:
					config = jsonnetConfig
				case ConfigFormatStarlark:
					config = starlarkConfig
				}

				dir := t.TempDir()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				sc := setup(ctx, t, dir, withGitea(true))
				defer sc.stop()

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
				user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				testutil.NilError(t, err)

				t.Logf("created agola user: %s", user.UserName)

				token := createAgolaUserToken(ctx, t, sc.config)

				// From now use the user token
				gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

				directRun(t, dir, config, configFormat, sc.config.Gateway.APIExposedURL, token, tt.args...)

				// TODO(sgotti) add an util to wait for a run phase
				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
					if err != nil {
						return false, nil
					}

					if len(runs) != 1 {
						return false, nil
					}

					run := runs[0]
					if run.Phase != rstypes.RunPhaseFinished {
						return false, nil
					}

					return true, nil
				})

				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(runs, 1))

				run, _, err := gwClient.GetUserRun(ctx, user.ID, runs[0].Number)
				testutil.NilError(t, err)

				assert.Equal(t, run.Phase, rstypes.RunPhaseFinished)
				assert.Equal(t, run.Result, rstypes.RunResultSuccess)

				var task *gwapitypes.RunResponseTask
				for _, t := range run.Tasks {
					if t.Name == "task01" {
						task = t
						break
					}
				}

				resp, err := gwClient.GetUserLogs(ctx, user.ID, run.Number, task.ID, false, 1, false)
				testutil.NilError(t, err)

				defer resp.Body.Close()

				logs, err := io.ReadAll(resp.Body)
				testutil.NilError(t, err)

				curEnv, err := testutil.ParseEnvs(bytes.NewReader(logs))
				testutil.NilError(t, err)

				// update commit sha from annotations since it will change at every test
				tt.env["COMMIT_SHA"] = run.Annotations["commit_sha"]

				for n, e := range tt.env {
					ce, ok := curEnv[n]
					assert.Assert(t, ok, "missing env var %s", n)
					assert.Equal(t, ce, e, "different env var %s value, want: %q, got %q", n, e, ce)
				}
			})
		}
	}
}

func TestRunEventsNotification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		config                 string
		expectedRunResult      rstypes.RunResult
		expectedRunPhase       rstypes.RunPhase
		expectedRunPhaseEvents []rstypes.RunPhase
		expectedRunTaskStatus  []rstypes.RunTaskStatus
	}{
		{
			name:                   "run result success",
			config:                 EnvRunConfig,
			expectedRunResult:      rstypes.RunResultSuccess,
			expectedRunPhase:       rstypes.RunPhaseFinished,
			expectedRunPhaseEvents: []rstypes.RunPhase{rstypes.RunPhaseQueued, rstypes.RunPhaseRunning, rstypes.RunPhaseRunning, rstypes.RunPhaseFinished},
			expectedRunTaskStatus:  []rstypes.RunTaskStatus{rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusSuccess, rstypes.RunTaskStatusSuccess},
		},
		{
			name:                   "run result failed",
			config:                 FailingRunConfig,
			expectedRunResult:      rstypes.RunResultFailed,
			expectedRunPhase:       rstypes.RunPhaseFinished,
			expectedRunPhaseEvents: []rstypes.RunPhase{rstypes.RunPhaseQueued, rstypes.RunPhaseRunning, rstypes.RunPhaseRunning, rstypes.RunPhaseFinished},
			expectedRunTaskStatus:  []rstypes.RunTaskStatus{rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusFailed, rstypes.RunTaskStatusFailed},
		},
		{
			name: "run setup config error",
			config: `
			{
				runserror:
			}
			`,
			expectedRunResult:      rstypes.RunResultUnknown,
			expectedRunPhase:       rstypes.RunPhaseSetupError,
			expectedRunPhaseEvents: []rstypes.RunPhase{rstypes.RunPhaseSetupError},
			expectedRunTaskStatus:  []rstypes.RunTaskStatus{rstypes.RunTaskStatusNotStarted},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			wrDir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wr := setupWebhooksReceiver(ctx, t, wrDir)
			defer wr.stop()

			sc := setup(ctx, t, dir, withGitea(true), withWebhooks(fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks"), webhookSecret))
			defer sc.stop()

			giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			testutil.NilError(t, err)

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			push(t, tt.config, giteaRepo.CloneURL, giteaToken, "commit", false)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) == 0 {
					return false, nil
				}
				if runs[0].Phase != tt.expectedRunPhase {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(runs, 1))

			assert.Equal(t, runs[0].Phase, tt.expectedRunPhase)
			assert.Equal(t, runs[0].Result, tt.expectedRunResult)

			run, _, err := gwClient.GetProjectRun(ctx, project.ID, runs[0].Number)
			testutil.NilError(t, err)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				webhooks, err := wr.webhooks.getWebhooks()
				testutil.NilError(t, err)

				if len(webhooks) < len(tt.expectedRunPhaseEvents) {
					return false, nil
				}

				return true, nil
			})

			webhooks, err := wr.webhooks.getWebhooks()
			testutil.NilError(t, err)

			for i, w := range webhooks {
				data, err := json.Marshal(w.webhookData)
				testutil.NilError(t, err)

				sig256 := hmac.New(sha256.New, []byte(sc.config.Notification.WebhookSecret))
				_, err = io.MultiWriter(sig256).Write(data)
				testutil.NilError(t, err)

				signatureSHA256 := hex.EncodeToString(sig256.Sum(nil))
				assert.Equal(t, signatureSHA256, w.signature)

				assert.Equal(t, w.webhookData.Run.Counter, run.Number)
				assert.Equal(t, w.webhookData.Run.Name, run.Name)
				assert.Equal(t, w.webhookData.Run.Phase, string(tt.expectedRunPhaseEvents[i]))
				assert.Assert(t, cmp.Len(w.webhookData.Run.Tasks, len(run.Tasks)))

				if len(run.Tasks) > 0 {
					var taskID string
					for id := range w.webhookData.Run.Tasks {
						taskID = id
					}
					whTask := w.webhookData.Run.Tasks[taskID]
					task := run.Tasks[taskID]

					assert.Equal(t, whTask.ID, task.ID)
					assert.Equal(t, whTask.Name, task.Name)
					assert.Equal(t, whTask.Status, string(tt.expectedRunTaskStatus[i]))
					assert.Assert(t, !whTask.Approved)
					assert.Assert(t, !whTask.Skip)
					assert.Assert(t, !whTask.Timedout)
					assert.Assert(t, !whTask.WaitingApproval)
					assert.Assert(t, cmp.Len(whTask.Steps, 1))
					assert.Equal(t, whTask.Level, 0)
				}
			}
		})
	}
}
