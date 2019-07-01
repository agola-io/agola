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

package datamanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	ostypes "agola.io/agola/internal/objectstorage/types"
	"agola.io/agola/internal/sequence"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

const (
	DefaultMaxDataFileSize = 10 * 1024 * 1024
)

type DataStatus struct {
	DataSequence string `json:"data_sequence,omitempty"`
	WalSequence  string `json:"wal_sequence,omitempty"`
	// an entry id ordered list of files for a specific data type (map key)
	Files map[string][]*DataStatusFile `json:"files,omitempty"`
}

type DataStatusFile struct {
	ID string `json:"id,omitempty"`
	// the last entry id in this file
	LastEntryID string `json:"last_entry_id,omitempty"`
}

type DataFileIndex struct {
	Index map[string]int64 `json:"index,omitempty"`
}

type DataEntry struct {
	ID       string `json:"id,omitempty"`
	DataType string `json:"data_type,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

func dataStatusPath(sequence string) string {
	return fmt.Sprintf("%s/%s.status", storageDataDir, sequence)
}

func DataFileIndexPath(dataType, id string) string {
	return fmt.Sprintf("%s/%s/%s.index", storageDataDir, dataType, id)
}

func DataFilePath(dataType, id string) string {
	return fmt.Sprintf("%s/%s/%s.data", storageDataDir, dataType, id)
}

// TODO(sgotti) this implementation could be heavily optimized to store less data in memory

// TODO(sgotti)
// split/merge data files at max N bytes (i.e 16MiB) so we'll rewrite only files
// with changed data

// walIndex is a map of dataType of id of walEntry
// TODO(sgotti) write this index to local disk (a temporary sqlite lite) instead of storing all in memory
type walIndex map[string]walActions

// walDataEntries is an order by id list of data entries
type walActions []*Action

func (w walActions) Len() int           { return len(w) }
func (w walActions) Less(i, j int) bool { return w[i].ID < w[j].ID }
func (w walActions) Swap(i, j int)      { w[i], w[j] = w[j], w[i] }

func (d *DataManager) walIndex(ctx context.Context, wals []*WalData) (walIndex, error) {
	wimap := map[string]map[string]*Action{}

	for _, walData := range wals {
		walFilef, err := d.ReadWal(walData.WalSequence)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(walFilef)
		var header *WalHeader
		if err = dec.Decode(&header); err != nil && err != io.EOF {
			walFilef.Close()
			return nil, err
		}
		walFilef.Close()

		walFile, err := d.ReadWalData(header.WalDataFileID)
		if err != nil {
			return nil, errors.Errorf("cannot read wal data file %q: %w", header.WalDataFileID, err)
		}
		defer walFile.Close()

		dec = json.NewDecoder(walFile)
		for {
			var action *Action

			err := dec.Decode(&action)
			if err == io.EOF {
				// all done
				break
			}
			if err != nil {
				return nil, errors.Errorf("failed to decode wal file: %w", err)
			}

			if _, ok := wimap[action.DataType]; !ok {
				wimap[action.DataType] = map[string]*Action{}
			}

			// only keep the last action for every entry id
			wimap[action.DataType][action.ID] = action
		}
	}

	wi := map[string]walActions{}
	for dataType, dd := range wimap {
		for _, de := range dd {
			wi[dataType] = append(wi[dataType], de)
		}
		sort.Sort(wi[dataType])
	}

	return wi, nil
}

// writeDataSnapshot will create a new data snapshot merging the uncheckpointed
// wals. It will split data files at maxDataFileSize bytes so we'll rewrite only
// files with changed data.
// Only new files will be created, previous snapshot data files won't be touched
//
// TODO(sgotti) add a function to merge small data files (i.e after deletions) to avoid fragmentation
// TODO(sgotti) add a function to delete old data files keeping only N snapshots
func (d *DataManager) writeDataSnapshot(ctx context.Context, wals []*WalData) error {
	dataSequence, err := sequence.IncSequence(ctx, d.e, etcdCheckpointSeqKey)
	if err != nil {
		return err
	}

	var lastWalSequence string
	for _, walData := range wals {
		lastWalSequence = walData.WalSequence
	}

	dataStatus := &DataStatus{
		DataSequence: dataSequence.String(),
		WalSequence:  lastWalSequence,
		Files:        make(map[string][]*DataStatusFile),
	}

	wi, err := d.walIndex(ctx, wals)
	if err != nil {
		return err
	}

	curDataStatus, err := d.GetLastDataStatus()
	if err != nil && err != ostypes.ErrNotExist {
		return err
	}

	for _, dataType := range d.dataTypes {
		var curDataStatusFiles []*DataStatusFile
		if curDataStatus != nil {
			curDataStatusFiles = curDataStatus.Files[dataType]
		}
		dataStatusFiles, err := d.writeDataType(ctx, wi, dataType, curDataStatusFiles)
		if err != nil {
			return err
		}
		dataStatus.Files[dataType] = dataStatusFiles
	}

	dataStatusj, err := json.Marshal(dataStatus)
	if err != nil {
		return err
	}
	if err := d.ost.WriteObject(dataStatusPath(dataSequence.String()), bytes.NewReader(dataStatusj), int64(len(dataStatusj)), true); err != nil {
		return err
	}

	return nil
}

func (d *DataManager) writeDataFile(ctx context.Context, buf *bytes.Buffer, size int64, dataFileIndex *DataFileIndex, dataFileID, dataType string) error {
	if buf.Len() == 0 {
		return fmt.Errorf("empty data entries")
	}

	if err := d.ost.WriteObject(DataFilePath(dataType, dataFileID), buf, size, true); err != nil {
		return err
	}

	dataFileIndexj, err := json.Marshal(dataFileIndex)
	if err != nil {
		return err
	}
	if err := d.ost.WriteObject(DataFileIndexPath(dataType, dataFileID), bytes.NewReader(dataFileIndexj), int64(len(dataFileIndexj)), true); err != nil {
		return err
	}

	return nil
}

type ActionGroup struct {
	DataStatusFile          *DataStatusFile
	StartActionIndex        int
	ActionsSize             int
	PreviousDataStatusFiles []*DataStatusFile
}

func (d *DataManager) actionGroups(ctx context.Context, wi walIndex, dataType string, curDataStatusFiles []*DataStatusFile) ([]*ActionGroup, []*DataStatusFile) {
	dataStatusFiles := []*DataStatusFile{}
	remainingDataStatusFiles := []*DataStatusFile{}

	actionGroups := []*ActionGroup{}

	var startActionIndex int
	var actionsSize int

	var actionIndex int
	var curDataStatusFileIndex int
	for {
		var action *Action
		if actionIndex <= len(wi[dataType])-1 {
			action = wi[dataType][actionIndex]
		}

		var curDataStatusFile *DataStatusFile
		if curDataStatusFileIndex <= len(curDataStatusFiles)-1 {
			curDataStatusFile = curDataStatusFiles[curDataStatusFileIndex]
		}

		if action == nil {
			if actionsSize > 0 {
				actionGroup := &ActionGroup{
					DataStatusFile:          curDataStatusFile,
					StartActionIndex:        startActionIndex,
					ActionsSize:             actionsSize,
					PreviousDataStatusFiles: dataStatusFiles,
				}
				actionGroups = append(actionGroups, actionGroup)
				curDataStatusFileIndex++
				if curDataStatusFileIndex <= len(curDataStatusFiles)-1 {
					remainingDataStatusFiles = curDataStatusFiles[curDataStatusFileIndex:]
				}
			}
			break
		}

		if curDataStatusFile != nil {
			if curDataStatusFile.LastEntryID >= action.ID || curDataStatusFileIndex == len(curDataStatusFiles)-1 {
				// continue using this status file
				actionIndex++
				actionsSize++
			} else {
				// find new status file
				if actionsSize > 0 {
					actionGroup := &ActionGroup{
						DataStatusFile:          curDataStatusFile,
						StartActionIndex:        startActionIndex,
						ActionsSize:             actionsSize,
						PreviousDataStatusFiles: dataStatusFiles,
					}
					actionGroups = append(actionGroups, actionGroup)

					startActionIndex = actionIndex
					actionsSize = 0
					dataStatusFiles = []*DataStatusFile{}
				} else {
					dataStatusFiles = append(dataStatusFiles, curDataStatusFile)
				}
				curDataStatusFileIndex++
			}
		} else {
			actionIndex++
			actionsSize++
		}
	}

	return actionGroups, remainingDataStatusFiles
}

func (d *DataManager) writeDataType(ctx context.Context, wi walIndex, dataType string, curDataStatusFiles []*DataStatusFile) ([]*DataStatusFile, error) {
	type SplitPoint struct {
		pos         int64
		lastEntryID string
	}

	if len(wi[dataType]) == 0 {
		// no actions
		return curDataStatusFiles, nil
	}
	actionGroups, remainingDataStatusFiles := d.actionGroups(ctx, wi, dataType, curDataStatusFiles)

	dataStatusFiles := []*DataStatusFile{}

	for _, actionGroup := range actionGroups {
		dataStatusFiles = append(dataStatusFiles, actionGroup.PreviousDataStatusFiles...)

		splitPoints := []SplitPoint{}
		dataFileIndexes := []*DataFileIndex{}
		dataFileIndex := &DataFileIndex{
			Index: make(map[string]int64),
		}
		dataEntries := []*DataEntry{}
		var buf bytes.Buffer
		var pos int64
		var lastEntryID string

		if actionGroup.DataStatusFile != nil {
			// TODO(sgotti) instead of reading all entries in memory decode it's contents one by one when needed
			oldDataf, err := d.ost.ReadObject(DataFilePath(dataType, actionGroup.DataStatusFile.ID))
			if err != nil && err != ostypes.ErrNotExist {
				return nil, err
			}
			if err != ostypes.ErrNotExist {
				dec := json.NewDecoder(oldDataf)
				for {
					var de *DataEntry

					err := dec.Decode(&de)
					if err == io.EOF {
						// all done
						break
					}
					if err != nil {
						oldDataf.Close()
						return nil, err
					}

					dataEntries = append(dataEntries, de)
				}
				oldDataf.Close()
			}
		}

		dataEntryIndex := 0
		actionIndex := actionGroup.StartActionIndex

		// iterate over data entries and action in order
		for {
			exists := false
			useAction := false

			var action *Action
			if actionIndex < actionGroup.StartActionIndex+actionGroup.ActionsSize {
				action = wi[dataType][actionIndex]
			}

			var de *DataEntry
			if dataEntryIndex <= len(dataEntries)-1 {
				de = dataEntries[dataEntryIndex]
			}

			if de == nil && action == nil {
				break
			}

			if action != nil {
				if de != nil {
					if de.ID == action.ID {
						exists = true
						useAction = true
					}
					if de.ID > action.ID {
						useAction = true
					}
				} else {
					useAction = true
				}

				if useAction {
					de = nil
					switch action.ActionType {
					case ActionTypePut:
						de = &DataEntry{
							ID:       action.ID,
							DataType: action.DataType,
							Data:     action.Data,
						}
						if exists {
							// replace current data entry with the action data
							dataEntryIndex++
						}
					case ActionTypeDelete:
						if exists {
							// skip current data entry
							dataEntryIndex++
						}
					}
					actionIndex++
				} else {
					dataEntryIndex++
				}
			} else {
				dataEntryIndex++
			}

			if de != nil {
				lastEntryID = de.ID
				dataEntryj, err := json.Marshal(de)
				if err != nil {
					return nil, err
				}
				if _, err := buf.Write(dataEntryj); err != nil {
					return nil, err
				}
				dataFileIndex.Index[de.ID] = pos
				prevPos := pos
				pos += int64(len(dataEntryj))
				var lastSplitPos int64
				if len(splitPoints) > 0 {
					lastSplitPos = splitPoints[len(splitPoints)-1].pos
				}
				if pos-lastSplitPos > d.maxDataFileSize {
					// add split point only if it's different (less) than the previous one
					if lastSplitPos < prevPos {
						splitPoints = append(splitPoints, SplitPoint{pos: int64(buf.Len()), lastEntryID: lastEntryID})
						dataFileIndexes = append(dataFileIndexes, dataFileIndex)
						dataFileIndex = &DataFileIndex{
							Index: make(map[string]int64),
						}
					}
				}
			}
		}

		// save remaining data
		if buf.Len() != 0 {
			var curPos int64
			var lastSplitPos int64
			if len(splitPoints) > 0 {
				lastSplitPos = splitPoints[len(splitPoints)-1].pos
			}
			// add final split point if there's something left in the buffer
			if lastSplitPos != int64(buf.Len()) {
				splitPoints = append(splitPoints, SplitPoint{pos: int64(buf.Len()), lastEntryID: lastEntryID})
			}
			dataFileIndexes = append(dataFileIndexes, dataFileIndex)
			for i, sp := range splitPoints {
				curDataFileID := uuid.NewV4().String()
				if err := d.writeDataFile(ctx, &buf, sp.pos-curPos, dataFileIndexes[i], curDataFileID, dataType); err != nil {
					return nil, err
				}
				// insert new dataStatusFile
				dataStatusFiles = append(dataStatusFiles, &DataStatusFile{
					ID:          curDataFileID,
					LastEntryID: sp.lastEntryID,
				})

				curPos = sp.pos
			}
		}

	}

	dataStatusFiles = append(dataStatusFiles, remainingDataStatusFiles...)

	return dataStatusFiles, nil
}

func (d *DataManager) Read(dataType, id string) (io.Reader, error) {
	curDataStatus, err := d.GetLastDataStatus()
	if err != nil {
		return nil, err
	}
	curFiles := curDataStatus.Files

	var matchingDataFileID string
	// get the matching data file for the action entry ID
	if len(curFiles[dataType]) == 0 {
		return nil, ostypes.ErrNotExist
	}

	matchingDataFileID = curFiles[dataType][0].ID
	for _, dataStatusFile := range curFiles[dataType] {
		if dataStatusFile.LastEntryID > id {
			matchingDataFileID = dataStatusFile.ID
			break
		}
	}

	dataFileIndexf, err := d.ost.ReadObject(DataFileIndexPath(dataType, matchingDataFileID))
	if err != nil {
		return nil, err
	}
	var dataFileIndex *DataFileIndex
	dec := json.NewDecoder(dataFileIndexf)
	err = dec.Decode(&dataFileIndex)
	if err != nil {
		dataFileIndexf.Close()
		return nil, err
	}
	dataFileIndexf.Close()

	pos, ok := dataFileIndex.Index[id]
	if !ok {
		return nil, ostypes.ErrNotExist
	}

	dataf, err := d.ost.ReadObject(DataFilePath(dataType, matchingDataFileID))
	if err != nil {
		return nil, err
	}
	if _, err := dataf.Seek(int64(pos), io.SeekStart); err != nil {
		dataf.Close()
		return nil, err
	}
	var de *DataEntry
	dec = json.NewDecoder(dataf)
	if err := dec.Decode(&de); err != nil {
		dataf.Close()
		return nil, err
	}
	dataf.Close()

	return bytes.NewReader(de.Data), nil
}

func (d *DataManager) GetLastDataStatusPath() (string, error) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	var dataStatusPath string
	for object := range d.ost.List(storageDataDir+"/", "", false, doneCh) {
		if object.Err != nil {
			return "", object.Err
		}
		if strings.HasSuffix(object.Path, ".status") {
			dataStatusPath = object.Path
		}
	}
	if dataStatusPath == "" {
		return "", ostypes.ErrNotExist
	}

	return dataStatusPath, nil
}

func (d *DataManager) GetLastDataStatus() (*DataStatus, error) {
	dataStatusPath, err := d.GetLastDataStatusPath()
	if err != nil {
		return nil, err
	}

	dataStatusf, err := d.ost.ReadObject(dataStatusPath)
	if err != nil {
		return nil, err
	}
	defer dataStatusf.Close()
	var dataStatus *DataStatus
	dec := json.NewDecoder(dataStatusf)

	return dataStatus, dec.Decode(&dataStatus)
}
