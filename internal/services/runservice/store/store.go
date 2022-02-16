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

package store

import (
	"fmt"
	"path"
	"strings"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/util"
)

func OSTRunTaskLogsBaseDir(rtID string) string {
	return path.Join("logs", rtID)
}

func OSTRunTaskLogsDataDir(rtID string) string {
	return path.Join(OSTRunTaskLogsBaseDir(rtID), "data")
}

func OSTRunTaskLogsRunsDir(rtID string) string {
	return path.Join(OSTRunTaskLogsBaseDir(rtID), "runs")
}

func OSTRunTaskSetupLogPath(rtID string) string {
	return path.Join(OSTRunTaskLogsDataDir(rtID), "setup.log")
}

func OSTRunTaskStepLogPath(rtID string, step int) string {
	return path.Join(OSTRunTaskLogsDataDir(rtID), "steps", fmt.Sprintf("%d.log", step))
}

func OSTRunTaskLogsRunPath(rtID, runID string) string {
	return path.Join(OSTRunTaskLogsRunsDir(rtID), runID)
}

func OSTArchivesBaseDir() string {
	return "workspacearchives"
}

func OSTRunTaskArchivesBaseDir(rtID string) string {
	return path.Join(OSTArchivesBaseDir(), rtID)
}

func OSTRunTaskArchivesDataDir(rtID string) string {
	return path.Join(OSTRunTaskArchivesBaseDir(rtID), "data")
}

func OSTRunTaskArchivesRunsDir(rtID string) string {
	return path.Join(OSTRunTaskArchivesBaseDir(rtID), "runs")
}

func OSTRunTaskArchivePath(rtID string, step int) string {
	return path.Join(OSTRunTaskArchivesDataDir(rtID), fmt.Sprintf("%d.tar", step))
}

func OSTRunTaskArchivesRunPath(rtID, runID string) string {
	return path.Join(OSTRunTaskArchivesRunsDir(rtID), runID)
}

func OSTRunTaskIDFromPath(archivePath string) (string, error) {
	pl := util.PathList(archivePath)
	if len(pl) < 2 {
		return "", errors.Errorf("wrong archive path %q", archivePath)
	}
	fmt.Printf("pl: %q\n", pl)
	if pl[0] != "workspacearchives" {
		return "", errors.Errorf("wrong archive path %q", archivePath)
	}
	return pl[1], nil
}

func OSTCacheDir() string {
	return "caches"
}

func OSTCachePath(key string) string {
	return path.Join(OSTCacheDir(), fmt.Sprintf("%s.tar", key))
}

func OSTCacheKey(p string) string {
	base := path.Base(p)
	return strings.TrimSuffix(base, path.Ext(base))
}
