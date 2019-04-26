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
	"strings"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/sequence"
)

type DataStatus struct {
	DataSequence string              `json:"data_sequence,omitempty"`
	WalSequence  string              `json:"wal_sequence,omitempty"`
	Files        map[string][]string `json:"files,omitempty"`
}

type DataFileIndex struct {
	Index map[string]int `json:"index,omitempty"`
}

type DataEntry struct {
	ID       string `json:"id,omitempty"`
	DataType string `json:"data_type,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

func dataStatusPath(sequence string) string {
	return fmt.Sprintf("%s/%s.status", storageDataDir, sequence)
}

func dataFileIndexPath(datatype, sequence string) string {
	return fmt.Sprintf("%s/%s/%s.index", storageDataDir, datatype, sequence)
}

func dataFilePath(datatype, sequence string) string {
	return fmt.Sprintf("%s/%s/%s.data", storageDataDir, datatype, sequence)
}

// TODO(sgotti)
// split/merge data files at max N bytes (i.e 16MiB) so we'll rewrite only files
// with changed data

func (d *DataManager) writeData(ctx context.Context, wals []*WalData) error {
	dataSequence, err := sequence.IncSequence(ctx, d.e, etcdWalSeqKey)
	if err != nil {
		return err
	}

	for _, dataType := range d.dataTypes {
		if err := d.writeDataType(ctx, wals, dataType, dataSequence.String()); err != nil {
			return err
		}
	}

	var lastWalSequence string
	for _, walData := range wals {
		lastWalSequence = walData.WalSequence
	}

	dataStatus := &DataStatus{
		DataSequence: dataSequence.String(),
		WalSequence:  lastWalSequence,
		Files:        make(map[string][]string),
	}
	for _, dataType := range d.dataTypes {
		dataStatus.Files[dataType] = []string{dataFilePath(dataType, dataSequence.String())}
	}

	dataStatusj, err := json.Marshal(dataStatus)
	if err != nil {
		return err
	}
	if err := d.ost.WriteObject(dataStatusPath(dataSequence.String()), bytes.NewReader(dataStatusj)); err != nil {
		return err
	}

	return nil
}

func (d *DataManager) writeDataType(ctx context.Context, wals []*WalData, datatype, dataSequence string) error {
	curDataStatus, err := d.GetLastDataStatus()
	if err != nil && err != objectstorage.ErrNotExist {
		return err
	}

	dataEntriesMap := map[string]*DataEntry{}
	if err != objectstorage.ErrNotExist {
		curDataSequence := curDataStatus.DataSequence

		oldDataf, err := d.ost.ReadObject(dataFilePath(datatype, curDataSequence))
		if err != nil && err != objectstorage.ErrNotExist {
			return err
		}
		if err != objectstorage.ErrNotExist {
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
					return err
				}
				dataEntriesMap[de.ID] = de
			}
			oldDataf.Close()
		}
	}

	for _, walData := range wals {
		walFilef, err := d.ReadWal(walData.WalSequence)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(walFilef)
		var header *WalHeader
		if err = dec.Decode(&header); err != nil && err != io.EOF {
			walFilef.Close()
			return err
		}
		walFilef.Close()

		walFile, err := d.ReadWalData(header.WalDataFileID)
		if err != nil {
			return errors.Wrapf(err, "cannot read wal data file %q", header.WalDataFileID)
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
				return errors.Wrapf(err, "failed to decode wal file")
			}
			if action.DataType != datatype {
				continue
			}

			switch action.ActionType {
			case ActionTypePut:
				de := &DataEntry{
					ID:       action.ID,
					DataType: action.DataType,
					Data:     action.Data,
				}
				dataEntriesMap[de.ID] = de
			case ActionTypeDelete:
				delete(dataEntriesMap, action.ID)
			}
		}
	}

	dataEntries := []*DataEntry{}
	for _, de := range dataEntriesMap {
		dataEntries = append(dataEntries, de)
	}

	dataFileIndex := &DataFileIndex{
		Index: make(map[string]int),
	}

	var buf bytes.Buffer
	pos := 0
	for _, de := range dataEntries {
		dataFileIndex.Index[de.ID] = pos

		dataEntryj, err := json.Marshal(de)
		if err != nil {
			return err
		}
		if _, err := buf.Write(dataEntryj); err != nil {
			return err
		}

		pos += len(dataEntryj)
	}
	if err := d.ost.WriteObject(dataFilePath(datatype, dataSequence), &buf); err != nil {
		return err
	}

	dataFileIndexj, err := json.Marshal(dataFileIndex)
	if err != nil {
		return err
	}
	if err := d.ost.WriteObject(dataFileIndexPath(datatype, dataSequence), bytes.NewReader(dataFileIndexj)); err != nil {
		return err
	}

	return nil
}

func (d *DataManager) Read(dataType, id string) (io.Reader, error) {
	curDataStatus, err := d.GetLastDataStatus()
	if err != nil {
		return nil, err
	}
	dataSequence := curDataStatus.DataSequence

	dataFileIndexf, err := d.ost.ReadObject(dataFileIndexPath(dataType, dataSequence))
	if err != nil {
		return nil, err
	}
	var dataFileIndex *DataFileIndex
	dec := json.NewDecoder(dataFileIndexf)
	err = dec.Decode(&dataFileIndex)
	if err != nil {
		dataFileIndexf.Close()
		return nil, errors.WithStack(err)
	}
	dataFileIndexf.Close()

	pos, ok := dataFileIndex.Index[id]
	if !ok {
		return nil, objectstorage.ErrNotExist
	}

	dataf, err := d.ost.ReadObject(dataFilePath(dataType, dataSequence))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err := dataf.Seek(int64(pos), io.SeekStart); err != nil {
		dataf.Close()
		return nil, errors.WithStack(err)
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
		return "", objectstorage.ErrNotExist
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
