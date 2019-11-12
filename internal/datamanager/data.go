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
	"container/ring"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/sequence"
	"agola.io/agola/internal/util"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

// ErrNoDataStatus represent when there's no data status files in the ost
var ErrNoDataStatus = errors.New("no data status files")

const (
	DefaultMaxDataFileSize = 10 * 1024 * 1024
	dataStatusToKeep       = 3
)

var (
	DataFileRegexp       = regexp.MustCompile(`^([a-zA-Z0-9]+-[a-zA-Z0-9]+)-([a-zA-Z0-9-]+)\.(data|index)$`)
	DataStatusFileRegexp = regexp.MustCompile(`^([a-zA-Z0-9]+-[a-zA-Z0-9]+)\.status$`)
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

func (d *DataManager) dataFileID(dataSequence *sequence.Sequence, next string) string {
	return fmt.Sprintf("%s-%s", dataSequence.String(), next)
}

func (d *DataManager) walIndex(ctx context.Context, wals []*WalData) (walIndex, error) {
	wimap := map[string]map[string]*Action{}

	for _, walData := range wals {
		header, err := d.ReadWal(walData.WalSequence)
		if err != nil {
			return nil, err
		}

		walFile, err := d.ReadWalData(header.WalDataFileID)
		if err != nil {
			return nil, errors.Errorf("cannot read wal data file %q: %w", header.WalDataFileID, err)
		}
		defer walFile.Close()

		dec := json.NewDecoder(walFile)
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

	curDataStatus, err := d.GetLastDataStatus()
	if err != nil && !errors.Is(err, ErrNoDataStatus) {
		return err
	}

	startWalIndex := 0
	if curDataStatus != nil {
		// skip wals already checkpointed in this data status
		for i, wal := range wals {
			if wal.WalSequence <= curDataStatus.WalSequence {
				continue
			}

			startWalIndex = i
			break
		}
	}

	wals = wals[startWalIndex:]

	wi, err := d.walIndex(ctx, wals)
	if err != nil {
		return err
	}

	for _, dataType := range d.dataTypes {
		var curDataStatusFiles []*DataStatusFile
		if curDataStatus != nil {
			curDataStatusFiles = curDataStatus.Files[dataType]
		}
		dataStatusFiles, err := d.writeDataType(ctx, wi, dataType, dataSequence, curDataStatusFiles)
		if err != nil {
			return err
		}
		dataStatus.Files[dataType] = dataStatusFiles
	}

	dataStatusj, err := json.Marshal(dataStatus)
	if err != nil {
		return err
	}
	if err := d.ost.WriteObject(d.dataStatusPath(dataSequence), bytes.NewReader(dataStatusj), int64(len(dataStatusj)), true); err != nil {
		return err
	}

	return nil
}

func (d *DataManager) writeDataFile(ctx context.Context, buf *bytes.Buffer, size int64, dataFileIndex *DataFileIndex, dataFileID, dataType string) error {
	if buf.Len() == 0 {
		return fmt.Errorf("empty data entries")
	}

	if err := d.ost.WriteObject(d.DataFilePath(dataType, dataFileID), buf, size, true); err != nil {
		return err
	}

	dataFileIndexj, err := json.Marshal(dataFileIndex)
	if err != nil {
		return err
	}
	if err := d.ost.WriteObject(d.DataFileIndexPath(dataType, dataFileID), bytes.NewReader(dataFileIndexj), int64(len(dataFileIndexj)), true); err != nil {
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

func (d *DataManager) writeDataType(ctx context.Context, wi walIndex, dataType string, dataSequence *sequence.Sequence, curDataStatusFiles []*DataStatusFile) ([]*DataStatusFile, error) {
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
			oldDataf, err := d.ost.ReadObject(d.DataFilePath(dataType, actionGroup.DataStatusFile.ID))
			if err != nil && !objectstorage.IsNotExist(err) {
				return nil, err
			}
			if !objectstorage.IsNotExist(err) {
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
				var lastSplitPos int64
				if len(splitPoints) > 0 {
					lastSplitPos = splitPoints[len(splitPoints)-1].pos
				}

				lastEntryID = de.ID
				dataEntryj, err := json.Marshal(de)
				if err != nil {
					return nil, err
				}
				if _, err := buf.Write(dataEntryj); err != nil {
					return nil, err
				}
				dataFileIndex.Index[de.ID] = pos - lastSplitPos
				prevPos := pos
				pos += int64(len(dataEntryj))
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

		// save data
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
				curDataFileID := d.dataFileID(dataSequence, uuid.NewV4().String())
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
		return nil, util.NewErrNotExist(errors.Errorf("datatype %q doesn't exists", dataType))
	}

	matchingDataFileID = curFiles[dataType][0].ID
	for _, dataStatusFile := range curFiles[dataType] {
		if dataStatusFile.LastEntryID >= id {
			matchingDataFileID = dataStatusFile.ID
			break
		}
	}

	dataFileIndexf, err := d.ost.ReadObject(d.DataFileIndexPath(dataType, matchingDataFileID))
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
		return nil, util.NewErrNotExist(errors.Errorf("datatype %q, id %q doesn't exists", dataType, id))
	}

	dataf, err := d.ost.ReadObject(d.DataFilePath(dataType, matchingDataFileID))
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

func (d *DataManager) GetFirstDataStatusSequences(n int) ([]*sequence.Sequence, error) {
	if n < 1 {
		return nil, errors.Errorf("n must be greater than 0")
	}

	dataStatusSequences := []*sequence.Sequence{}
	c := 0

	doneCh := make(chan struct{})
	defer close(doneCh)
	for object := range d.ost.List(d.storageDataDir()+"/", "", false, doneCh) {
		if object.Err != nil {
			return nil, object.Err
		}
		if m := DataStatusFileRegexp.FindStringSubmatch(path.Base(object.Path)); m != nil {
			seq, err := sequence.Parse(m[1])
			if err != nil {
				d.log.Warnf("cannot parse sequence for data status file %q", object.Path)
				continue
			}
			dataStatusSequences = append(dataStatusSequences, seq)
			c++
		} else {
			d.log.Warnf("bad file %q found in storage data dir", object.Path)
		}
		if c >= n {
			break
		}
	}

	if len(dataStatusSequences) == 0 {
		return nil, ErrNoDataStatus
	}

	return dataStatusSequences, nil
}

func (d *DataManager) GetLastDataStatusSequences(n int) ([]*sequence.Sequence, error) {
	if n < 1 {
		return nil, errors.Errorf("n must be greater than 0")
	}
	r := ring.New(n)
	re := r

	doneCh := make(chan struct{})
	defer close(doneCh)

	for object := range d.ost.List(d.storageDataDir()+"/", "", false, doneCh) {
		if object.Err != nil {
			return nil, object.Err
		}
		if m := DataStatusFileRegexp.FindStringSubmatch(path.Base(object.Path)); m != nil {
			seq, err := sequence.Parse(m[1])
			if err != nil {
				d.log.Warnf("cannot parse sequence for data status file %q", object.Path)
				continue
			}
			re.Value = seq
			re = re.Next()
		} else {
			d.log.Warnf("bad file %q found in storage data dir", object.Path)
		}
	}

	dataStatusSequences := []*sequence.Sequence{}
	re.Do(func(x interface{}) {
		if x != nil {
			dataStatusSequences = append([]*sequence.Sequence{x.(*sequence.Sequence)}, dataStatusSequences...)
		}
	})

	if len(dataStatusSequences) == 0 {
		return nil, ErrNoDataStatus
	}

	return dataStatusSequences, nil
}

func (d *DataManager) GetDataStatus(dataSequence *sequence.Sequence) (*DataStatus, error) {
	dataStatusf, err := d.ost.ReadObject(d.dataStatusPath(dataSequence))
	if err != nil {
		return nil, err
	}
	defer dataStatusf.Close()
	var dataStatus *DataStatus
	dec := json.NewDecoder(dataStatusf)

	return dataStatus, dec.Decode(&dataStatus)
}

func (d *DataManager) GetFirstDataStatusSequence() (*sequence.Sequence, error) {
	dataStatusSequences, err := d.GetFirstDataStatusSequences(1)
	if err != nil {
		return nil, err
	}

	return dataStatusSequences[0], nil
}

func (d *DataManager) GetLastDataStatusSequence() (*sequence.Sequence, error) {
	dataStatusSequences, err := d.GetLastDataStatusSequences(1)
	if err != nil {
		return nil, err
	}

	return dataStatusSequences[0], nil
}

func (d *DataManager) GetFirstDataStatus() (*DataStatus, error) {
	dataStatusSequence, err := d.GetFirstDataStatusSequence()
	if err != nil {
		return nil, err
	}

	return d.GetDataStatus(dataStatusSequence)
}

func (d *DataManager) GetLastDataStatus() (*DataStatus, error) {
	dataStatusSequence, err := d.GetLastDataStatusSequence()
	if err != nil {
		return nil, err
	}

	return d.GetDataStatus(dataStatusSequence)
}

func (d *DataManager) Export(ctx context.Context, w io.Writer) error {
	if err := d.checkpoint(ctx, true); err != nil {
		return err
	}

	curDataStatus, err := d.GetLastDataStatus()
	if err != nil {
		return err
	}

	for _, dataType := range d.dataTypes {
		var curDataStatusFiles []*DataStatusFile
		if curDataStatus != nil {
			curDataStatusFiles = curDataStatus.Files[dataType]
		}
		for _, dsf := range curDataStatusFiles {
			dataf, err := d.ost.ReadObject(d.DataFilePath(dataType, dsf.ID))
			if err != nil {
				return err
			}
			if _, err := io.Copy(w, dataf); err != nil {
				dataf.Close()
				return err
			}

			dataf.Close()
		}
	}

	return nil
}

func (d *DataManager) Import(ctx context.Context, r io.Reader) error {
	// delete contents in etcd
	if err := d.deleteEtcd(ctx); err != nil {
		return err
	}

	// we require all entries of the same datatypes grouped together
	seenDataTypes := map[string]struct{}{}

	// create a new sequence, we assume that it'll be greater than previous data sequences
	dataSequence, err := sequence.IncSequence(ctx, d.e, etcdCheckpointSeqKey)
	if err != nil {
		return err
	}

	dataStatus := &DataStatus{
		DataSequence: dataSequence.String(),
		// no last wal sequence on import
		WalSequence: "",
		Files:       make(map[string][]*DataStatusFile),
	}

	dataStatusFiles := []*DataStatusFile{}

	var lastEntryID string
	var curDataType string
	var buf bytes.Buffer
	var pos int64
	dataFileIndex := &DataFileIndex{
		Index: make(map[string]int64),
	}
	dec := json.NewDecoder(r)

	for {
		var de *DataEntry

		err := dec.Decode(&de)
		if err == io.EOF {
			dataFileID := d.dataFileID(dataSequence, uuid.NewV4().String())
			if err := d.writeDataFile(ctx, &buf, int64(buf.Len()), dataFileIndex, dataFileID, curDataType); err != nil {
				return err
			}

			dataStatusFiles = append(dataStatusFiles, &DataStatusFile{
				ID:          dataFileID,
				LastEntryID: lastEntryID,
			})
			dataStatus.Files[curDataType] = dataStatusFiles

			break
		}

		if curDataType == "" {
			curDataType = de.DataType
			seenDataTypes[de.DataType] = struct{}{}
		}

		mustWrite := false
		mustReset := false
		if pos > d.maxDataFileSize {
			mustWrite = true
		}

		if curDataType != de.DataType {
			if _, ok := seenDataTypes[de.DataType]; ok {
				return errors.Errorf("dataType %q already imported", de.DataType)
			}
			mustWrite = true
			mustReset = true
		}

		if mustWrite {
			dataFileID := d.dataFileID(dataSequence, uuid.NewV4().String())
			if err := d.writeDataFile(ctx, &buf, int64(buf.Len()), dataFileIndex, dataFileID, curDataType); err != nil {
				return err
			}

			dataStatusFiles = append(dataStatusFiles, &DataStatusFile{
				ID:          dataFileID,
				LastEntryID: lastEntryID,
			})

			if mustReset {
				dataStatus.Files[curDataType] = dataStatusFiles

				dataStatusFiles = []*DataStatusFile{}
				curDataType = de.DataType
				lastEntryID = ""
			}

			dataFileIndex = &DataFileIndex{
				Index: make(map[string]int64),
			}
			buf = bytes.Buffer{}
			pos = 0
		}

		if de.ID <= lastEntryID {
			// entries for the same datatype must be unique and ordered
			return errors.Errorf("entry id %q is less or equal than previous entry id %q", de.ID, lastEntryID)
		}
		lastEntryID = de.ID

		dataEntryj, err := json.Marshal(de)
		if err != nil {
			return err
		}
		if _, err := buf.Write(dataEntryj); err != nil {
			return err
		}
		dataFileIndex.Index[de.ID] = pos
		pos += int64(len(dataEntryj))
	}

	dataStatusj, err := json.Marshal(dataStatus)
	if err != nil {
		return err
	}
	if err := d.ost.WriteObject(d.dataStatusPath(dataSequence), bytes.NewReader(dataStatusj), int64(len(dataStatusj)), true); err != nil {
		return err
	}

	// initialize etcd providing the specific datastatus
	if err := d.InitEtcd(ctx, dataStatus); err != nil {
		return err
	}

	return nil
}

func (d *DataManager) CleanOldCheckpoints(ctx context.Context) error {
	dataStatusSequences, err := d.GetLastDataStatusSequences(dataStatusToKeep)
	if err != nil {
		return err
	}

	return d.cleanOldCheckpoints(ctx, dataStatusSequences)
}

func (d *DataManager) cleanOldCheckpoints(ctx context.Context, dataStatusSequences []*sequence.Sequence) error {
	if len(dataStatusSequences) == 0 {
		return nil
	}

	lastDataStatusSequence := dataStatusSequences[0]

	// Remove old data status paths
	if len(dataStatusSequences) >= dataStatusToKeep {
		dataStatusPathsMap := map[string]struct{}{}
		for _, seq := range dataStatusSequences {
			dataStatusPathsMap[d.dataStatusPath(seq)] = struct{}{}
		}

		doneCh := make(chan struct{})
		defer close(doneCh)
		for object := range d.ost.List(d.storageDataDir()+"/", "", false, doneCh) {
			if object.Err != nil {
				return object.Err
			}

			skip := false
			if m := DataStatusFileRegexp.FindStringSubmatch(path.Base(object.Path)); m != nil {
				seq, err := sequence.Parse(m[1])
				if err == nil && seq.String() > lastDataStatusSequence.String() {
					d.log.Infof("skipping file %q since its sequence is greater than %q", object.Path, lastDataStatusSequence)
					skip = true
				}
			}
			if skip {
				continue
			}

			if _, ok := dataStatusPathsMap[object.Path]; !ok {
				d.log.Infof("removing %q", object.Path)
				if err := d.ost.DeleteObject(object.Path); err != nil {
					if !objectstorage.IsNotExist(err) {
						return err
					}
				}
			}
		}
	}

	// A list of files to keep
	files := map[string]struct{}{}

	for _, dataStatusSequence := range dataStatusSequences {
		dataStatus, err := d.GetDataStatus(dataStatusSequence)
		if err != nil {
			return err
		}

		for dataType := range dataStatus.Files {
			for _, file := range dataStatus.Files[dataType] {
				files[d.DataFileBasePath(dataType, file.ID)] = struct{}{}
			}
		}
	}

	doneCh := make(chan struct{})
	defer close(doneCh)

	for object := range d.ost.List(d.storageDataDir()+"/", "", true, doneCh) {
		if object.Err != nil {
			return object.Err
		}

		p := object.Path
		// object file relative to the storageDataDir
		pr := strings.TrimPrefix(p, d.storageDataDir()+"/")
		// object file full path without final extension
		pne := strings.TrimSuffix(p, path.Ext(p))
		// object file base name
		pb := path.Base(p)

		// skip status files
		if !strings.Contains(pr, "/") && strings.HasSuffix(pr, ".status") {
			continue
		}

		// skip data files with a sequence greater than the last known sequence.
		// this is to avoid possible conditions where there's a Clean concurrent
		// with a running Checkpoint (also if protect by etcd locks, they cannot
		// enforce these kind of operations that are acting on resources
		// external to etcd during network errors) that will remove the objects
		// created by this checkpoint since the data status file doesn't yet
		// exist.
		skip := false
		// extract the data sequence from the object name
		if m := DataFileRegexp.FindStringSubmatch(pb); m != nil {
			seq, err := sequence.Parse(m[1])
			if err == nil && seq.String() > lastDataStatusSequence.String() {
				d.log.Infof("skipping file %q since its sequence is greater than %q", p, lastDataStatusSequence)
				skip = true
			}
		}
		if skip {
			continue
		}

		if _, ok := files[pne]; !ok {
			d.log.Infof("removing %q", object.Path)
			if err := d.ost.DeleteObject(object.Path); err != nil {
				if !objectstorage.IsNotExist(err) {
					return err
				}
			}
		}
	}

	return nil
}
