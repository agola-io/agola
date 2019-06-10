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

package types

type RunType string

const (
	RunTypeProject RunType = "project"
	RunTypeUser    RunType = "user"
)

type RunRefType string

const (
	RunRefTypeBranch      RunRefType = "branch"
	RunRefTypeTag         RunRefType = "tag"
	RunRefTypePullRequest RunRefType = "pull_request"
)

type RunCreationTriggerType string

const (
	RunCreationTriggerTypeWebhook RunCreationTriggerType = "webhook"
)
