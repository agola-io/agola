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

package action

import (
	"context"
	"net/url"
	"path"

	"agola.io/agola/internal/services/common"
	rstypes "agola.io/agola/services/runservice/types"
)

// GetBadge return a badge for a project branch
// TODO(sgotti) also handle tags and PRs
func (h *ActionHandler) GetBadge(ctx context.Context, projectRef, branch string) (string, error) {
	project, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return "", ErrFromRemote(resp, err)
	}

	// if branch is empty we get the latest run for every branch.
	group := path.Join("/", string(common.GroupTypeProject), project.ID, string(common.GroupTypeBranch), url.PathEscape(branch))
	runResp, resp, err := h.runserviceClient.GetGroupLastRun(ctx, group, nil)
	if err != nil {
		return "", ErrFromRemote(resp, err)
	}
	if len(runResp.Runs) == 0 {
		return badgeUnknown, nil
	}
	run := runResp.Runs[0]

	var badge string
	switch run.Result {
	case rstypes.RunResultUnknown:
		switch run.Phase {
		case rstypes.RunPhaseSetupError:
			badge = badgeError
		case rstypes.RunPhaseQueued:
			badge = badgeInProgress
		case rstypes.RunPhaseRunning:
			badge = badgeInProgress
		case rstypes.RunPhaseCancelled:
			badge = badgeFailed
		}
	case rstypes.RunResultSuccess:
		badge = badgeSuccess
	case rstypes.RunResultFailed:
		badge = badgeFailed
	case rstypes.RunResultStopped:
		badge = badgeFailed
	}

	return badge, nil
}

// svg images generated from shields.io
const (
	// https://img.shields.io/badge/run-unknown-inactive.svg
	badgeUnknown = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="90" height="20"><linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="a"><rect width="90" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#a)"><path fill="#555" d="M0 0h29v20H0z"/><path fill="#9f9f9f" d="M29 0h61v20H29z"/><path fill="url(#b)" d="M0 0h90v20H0z"/></g><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110"> <text x="155" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="190">run</text><text x="155" y="140" transform="scale(.1)" textLength="190">run</text><text x="585" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="510">unknown</text><text x="585" y="140" transform="scale(.1)" textLength="510">unknown</text></g> </svg>`
	// https://img.shields.io/badge/run-success-success.svg
	badgeSuccess = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="82" height="20"><linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="a"><rect width="82" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#a)"><path fill="#555" d="M0 0h29v20H0z"/><path fill="#4c1" d="M29 0h53v20H29z"/><path fill="url(#b)" d="M0 0h82v20H0z"/></g><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110"> <text x="155" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="190">run</text><text x="155" y="140" transform="scale(.1)" textLength="190">run</text><text x="545" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="430">success</text><text x="545" y="140" transform="scale(.1)" textLength="430">success</text></g> </svg>`
	// https://img.shields.io/badge/run-failed-critical.svg
	badgeFailed = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="68" height="20"><linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="a"><rect width="68" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#a)"><path fill="#555" d="M0 0h29v20H0z"/><path fill="#e05d44" d="M29 0h39v20H29z"/><path fill="url(#b)" d="M0 0h68v20H0z"/></g><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110"> <text x="155" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="190">run</text><text x="155" y="140" transform="scale(.1)" textLength="190">run</text><text x="475" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="290">failed</text><text x="475" y="140" transform="scale(.1)" textLength="290">failed</text></g> </svg>`
	// https://img.shields.io/badge/run-inprogress-informational.svg
	badgeInProgress = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="96" height="20"><linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="a"><rect width="96" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#a)"><path fill="#555" d="M0 0h29v20H0z"/><path fill="#007ec6" d="M29 0h67v20H29z"/><path fill="url(#b)" d="M0 0h96v20H0z"/></g><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110"> <text x="155" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="190">run</text><text x="155" y="140" transform="scale(.1)" textLength="190">run</text><text x="615" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="570">inprogress</text><text x="615" y="140" transform="scale(.1)" textLength="570">inprogress</text></g> </svg>`
	// https://img.shields.io/badge/run-error-yellow.svg
	badgeError = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="66" height="20"><linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="a"><rect width="66" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#a)"><path fill="#555" d="M0 0h29v20H0z"/><path fill="#dfb317" d="M29 0h37v20H29z"/><path fill="url(#b)" d="M0 0h66v20H0z"/></g><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110"> <text x="155" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="190">run</text><text x="155" y="140" transform="scale(.1)" textLength="190">run</text><text x="465" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="270">error</text><text x="465" y="140" transform="scale(.1)" textLength="270">error</text></g> </svg>`
)
