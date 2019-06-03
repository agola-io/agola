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

package datamanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/objectstorage/posix"
	ostypes "github.com/sorintlab/agola/internal/objectstorage/types"
	"github.com/sorintlab/agola/internal/testutil"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

func setupEtcd(t *testing.T, dir string) *testutil.TestEmbeddedEtcd {
	tetcd, err := testutil.NewTestEmbeddedEtcd(t, logger, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tetcd.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tetcd.WaitUp(30 * time.Second); err != nil {
		t.Fatalf("error waiting on store up: %v", err)
	}
	return tetcd
}

func shutdownEtcd(tetcd *testutil.TestEmbeddedEtcd) {
	if tetcd.Etcd != nil {
		tetcd.Kill()
	}
}

type noopCheckpointer struct {
}

func (c *noopCheckpointer) Checkpoint(ctx context.Context, action *Action) error {
	return nil
}

func TestEtcdReset(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx, cancel := context.WithCancel(context.Background())

	ostDir, err := ioutil.TempDir(dir, "ost")

	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	dmConfig := &DataManagerConfig{
		BasePath:        "basepath",
		E:               tetcd.TestEtcd.Store,
		OST:             objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum: 10,
		DataTypes:       []string{"datatype01"},
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)
	dmReadyCh := make(chan struct{})

	t.Logf("starting datamanager")
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			DataType:   "datatype01",
			Data:       []byte("{}"),
		},
	}

	expectedObjects := []string{}
	for i := 0; i < 20; i++ {
		objectID := fmt.Sprintf("object%02d", i)
		expectedObjects = append(expectedObjects, objectID)
		actions[0].ID = objectID
		if _, err := dm.WriteWal(ctx, actions, nil); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	// wait for wal to be committed storage
	time.Sleep(5 * time.Second)

	t.Logf("stopping datamanager")
	cancel()

	t.Logf("stopping etcd")
	// Reset etcd
	shutdownEtcd(tetcd)
	tetcd.WaitDown(10 * time.Second)
	t.Logf("resetting etcd")
	os.RemoveAll(etcdDir)
	t.Logf("starting etcd")
	tetcd = setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)
	if err := tetcd.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer shutdownEtcd(tetcd)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	dmConfig = &DataManagerConfig{
		BasePath:        "basepath",
		E:               tetcd.TestEtcd.Store,
		OST:             objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum: 10,
		DataTypes:       []string{"datatype01"},
	}
	dm, err = NewDataManager(ctx, logger, dmConfig)
	dmReadyCh = make(chan struct{})

	t.Logf("starting datamanager")
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	time.Sleep(5 * time.Second)

	for i := 0; i < 20; i++ {
		objectID := fmt.Sprintf("object%02d", i)
		_, _, err = dm.ReadObject("datatype01", objectID, nil)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}
}

func TestConcurrentUpdate(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")

	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	dmConfig := &DataManagerConfig{
		E:               tetcd.TestEtcd.Store,
		OST:             objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum: 10,
		DataTypes:       []string{"datatype01"},
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			ID:         "object01",
			DataType:   "datatype01",
			Data:       []byte("{}"),
		},
	}

	dmReadyCh := make(chan struct{})
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	time.Sleep(5 * time.Second)

	cgNames := []string{"changegroup01", "changegroup02"}
	cgt, err := dm.GetChangeGroupsUpdateToken(cgNames)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// populate with a wal
	cgt, err = dm.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must work successfully
	oldcgt := cgt
	cgt, err = dm.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must fail since we are using the old cgt
	_, err = dm.WriteWal(ctx, actions, oldcgt)
	if err != ErrConcurrency {
		t.Fatalf("expected err: %v, got %v", ErrConcurrency, err)
	}

	// this must work successfully
	cgt, err = dm.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must fail since we are using the old cgt
	oldcgt = cgt
	cgt, err = dm.WriteWal(ctx, actions, cgt)
	_, err = dm.WriteWal(ctx, actions, oldcgt)
	if err != ErrConcurrency {
		t.Fatalf("expected err: %v, got %v", ErrConcurrency, err)
	}
}

func TestWalCleaner(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")

	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	walKeepNum := 10
	dmConfig := &DataManagerConfig{
		E:                    tetcd.TestEtcd.Store,
		OST:                  objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum:      walKeepNum,
		DataTypes:            []string{"datatype01"},
		MinCheckpointWalsNum: 1,
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			ID:         "object01",
			DataType:   "datatype01",
			Data:       []byte("{}"),
		},
	}

	dmReadyCh := make(chan struct{})
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	for i := 0; i < 20; i++ {
		if _, err := dm.WriteWal(ctx, actions, nil); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	if err := dm.checkpoint(ctx); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := dm.walCleaner(ctx); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	walsCount := 0
	for range dm.ListEtcdWals(ctx, 0) {
		walsCount++
	}
	if walsCount != walKeepNum {
		t.Fatalf("expected %d wals in etcd, got %d wals", walKeepNum, walsCount)
	}
}

func TestReadObject(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")
	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	dmConfig := &DataManagerConfig{
		E:   tetcd.TestEtcd.Store,
		OST: objectstorage.NewObjStorage(ost, "/"),
		// remove almost all wals to see that they are removed also from changes
		EtcdWalsKeepNum: 1,
		DataTypes:       []string{"datatype01"},
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)

	dmReadyCh := make(chan struct{})
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	time.Sleep(5 * time.Second)

	actions := []*Action{}
	for i := 0; i < 20; i++ {
		actions = append(actions, &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d" }`, i)),
		})
	}

	// populate with a wal
	_, err = dm.WriteWal(ctx, actions, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// wait for the event to be read
	time.Sleep(500 * time.Millisecond)
	// should read it
	_, _, err = dm.ReadObject("datatype01", "object1", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, _, err = dm.ReadObject("datatype01", "object19", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	actions = []*Action{}
	for i := 0; i < 10; i++ {
		actions = append(actions, &Action{
			ActionType: ActionTypeDelete,
			ID:         fmt.Sprintf("object%d", i),
			DataType:   "datatype01",
		})
	}

	_, err = dm.WriteWal(ctx, actions, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// wait for the event to be read
	time.Sleep(500 * time.Millisecond)

	// test read from changes (since not checkpoint yet)

	// should not exists
	_, _, err = dm.ReadObject("datatype01", "object1", nil)
	if err != ostypes.ErrNotExist {
		t.Fatalf("expected err %v, got: %v", ostypes.ErrNotExist, err)
	}
	// should exist
	_, _, err = dm.ReadObject("datatype01", "object19", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// do a checkpoint and wal clean
	if err := dm.checkpoint(ctx); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := dm.walCleaner(ctx); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// wait for the event to be read
	time.Sleep(500 * time.Millisecond)

	// test read from data

	// should not exists
	_, _, err = dm.ReadObject("datatype01", "object1", nil)
	if err != ostypes.ErrNotExist {
		t.Fatalf("expected err %v, got: %v", ostypes.ErrNotExist, err)
	}
	// should exist
	_, _, err = dm.ReadObject("datatype01", "object19", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func testCheckpoint(t *testing.T, ctx context.Context, dm *DataManager, actionGroups [][]*Action, currentEntries map[string]*DataEntry) (map[string]*DataEntry, error) {
	expectedEntries := map[string]*DataEntry{}
	for _, e := range currentEntries {
		expectedEntries[e.ID] = e
	}

	for _, actionGroup := range actionGroups {
		for _, action := range actionGroup {
			switch action.ActionType {
			case ActionTypePut:
				expectedEntries[action.ID] = &DataEntry{ID: action.ID, DataType: action.DataType, Data: action.Data}
			case ActionTypeDelete:
				delete(expectedEntries, action.ID)
			}
		}
	}

	for _, actionGroup := range actionGroups {
		// populate with a wal
		_, err := dm.WriteWal(ctx, actionGroup, nil)
		if err != nil {
			return nil, err
		}
	}

	// wait for the event to be read
	time.Sleep(500 * time.Millisecond)

	// do a checkpoint
	if err := dm.checkpoint(ctx); err != nil {
		return nil, err
	}

	if err := checkDataFiles(ctx, t, dm, expectedEntries); err != nil {
		return nil, err
	}

	return expectedEntries, nil
}

// TODO(sgotti) some fuzzy testing will be really good
func TestCheckpoint(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")
	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	dmConfig := &DataManagerConfig{
		E:   tetcd.TestEtcd.Store,
		OST: objectstorage.NewObjStorage(ost, "/"),
		// remove almost all wals to see that they are removed also from changes
		EtcdWalsKeepNum: 1,
		DataTypes:       []string{"datatype01"},
		// checkpoint also with only one wal
		MinCheckpointWalsNum: 1,
		// use a small maxDataFileSize
		MaxDataFileSize: 10 * 1024,
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)
	dmReadyCh := make(chan struct{})
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	time.Sleep(5 * time.Second)

	contents := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// test insert from scratch (no current entries)
	actions := []*Action{}
	for i := 200; i < 400; i++ {
		action := &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}

	currentEntries, err := testCheckpoint(t, ctx, dm, [][]*Action{actions}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// test delete of all existing entries
	actions = []*Action{}
	for i := 200; i < 400; i++ {
		actions = append(actions, &Action{
			ActionType: ActionTypeDelete,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
		})
	}

	currentEntries, err = testCheckpoint(t, ctx, dm, [][]*Action{actions}, currentEntries)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// test insert from scratch again (no current entries)
	actions = []*Action{}
	for i := 200; i < 400; i++ {
		action := &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}

	currentEntries, err = testCheckpoint(t, ctx, dm, [][]*Action{actions}, currentEntries)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// test delete some existing entries in the middle
	actions = []*Action{}
	for i := 250; i < 350; i++ {
		action := &Action{
			ActionType: ActionTypeDelete,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
		}
		actions = append(actions, action)
	}

	currentEntries, err = testCheckpoint(t, ctx, dm, [][]*Action{actions}, currentEntries)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// test delete of unexisting entries
	actions = []*Action{}
	for i := 1000; i < 1010; i++ {
		action := &Action{
			ActionType: ActionTypeDelete,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
		}
		actions = append(actions, action)
	}

	currentEntries, err = testCheckpoint(t, ctx, dm, [][]*Action{actions}, currentEntries)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// test update and insert at the end
	actions = []*Action{}
	for i := 300; i < 500; i++ {
		action := &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}

	currentEntries, err = testCheckpoint(t, ctx, dm, [][]*Action{actions}, currentEntries)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// test update and insert at the start
	actions = []*Action{}
	for i := 0; i < 300; i++ {
		action := &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}

	currentEntries, err = testCheckpoint(t, ctx, dm, [][]*Action{actions}, currentEntries)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// test multiple wals with different insert, updated, deletes
	actionGroups := [][]*Action{}
	for i := 0; i < 150; i++ {
		action := &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}
	actionGroups = append(actionGroups, actions)
	for i := 50; i < 100; i++ {
		action := &Action{
			ActionType: ActionTypeDelete,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}
	actionGroups = append(actionGroups, actions)
	for i := 250; i < 300; i++ {
		action := &Action{
			ActionType: ActionTypeDelete,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}
	for i := 70; i < 80; i++ {
		action := &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%04d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d", "Contents": %s }`, i, contents)),
		}
		actions = append(actions, action)
	}
	actionGroups = append(actionGroups, actions)

	currentEntries, err = testCheckpoint(t, ctx, dm, actionGroups, currentEntries)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func checkDataFiles(ctx context.Context, t *testing.T, dm *DataManager, expectedEntriesMap map[string]*DataEntry) error {
	// read the data file
	curDataStatus, err := dm.GetLastDataStatus()
	if err != nil {
		return err
	}

	allEntriesMap := map[string]*DataEntry{}
	var prevLastEntryID string

	for i, file := range curDataStatus.Files["datatype01"] {
		dataFileIndexf, err := dm.ost.ReadObject(DataFileIndexPath("datatype01", file.ID))
		if err != nil {
			return err
		}
		var dataFileIndex *DataFileIndex
		dec := json.NewDecoder(dataFileIndexf)
		err = dec.Decode(&dataFileIndex)
		if err != nil {
			dataFileIndexf.Close()
			return err
		}

		dataFileIndexf.Close()
		dataEntriesMap := map[string]*DataEntry{}
		dataEntries := []*DataEntry{}
		dataf, err := dm.ost.ReadObject(DataFilePath("datatype01", file.ID))
		if err != nil {
			return err
		}
		dec = json.NewDecoder(dataf)
		var prevEntryID string
		for {
			var de *DataEntry

			err := dec.Decode(&de)
			if err == io.EOF {
				// all done
				break
			}
			if err != nil {
				dataf.Close()
				return err
			}
			// check that there are no duplicate entries
			if _, ok := allEntriesMap[de.ID]; ok {
				return fmt.Errorf("duplicate entry id: %s", de.ID)
			}
			// check that the entries are in order
			if de.ID < prevEntryID {
				return fmt.Errorf("previous entry id: %s greater than entry id: %s", prevEntryID, de.ID)
			}

			dataEntriesMap[de.ID] = de
			dataEntries = append(dataEntries, de)
			allEntriesMap[de.ID] = de
		}
		dataf.Close()

		// check that the index matches the entries
		if len(dataFileIndex.Index) != len(dataEntriesMap) {
			return fmt.Errorf("index entries: %d different than data entries: %d", len(dataFileIndex.Index), len(dataEntriesMap))
		}
		indexIDs := make([]string, len(dataFileIndex.Index))
		entriesIDs := make([]string, len(dataEntriesMap))
		for id := range dataFileIndex.Index {
			indexIDs = append(indexIDs, id)
		}
		for id := range dataEntriesMap {
			entriesIDs = append(entriesIDs, id)
		}
		sort.Strings(indexIDs)
		sort.Strings(entriesIDs)
		if !reflect.DeepEqual(indexIDs, entriesIDs) {
			return fmt.Errorf("index entries ids don't match data entries ids: index: %v, data: %v", indexIDs, entriesIDs)
		}

		if file.LastEntryID != dataEntries[len(dataEntries)-1].ID {
			return fmt.Errorf("lastEntryID for datafile %d: %s is different than real last entry id: %s", i, file.LastEntryID, dataEntries[len(dataEntries)-1].ID)
		}

		// check that all the files are in order
		if file.LastEntryID == prevLastEntryID {
			return fmt.Errorf("lastEntryID for datafile %d is equal than previous file lastEntryID: %s == %s", i, file.LastEntryID, prevLastEntryID)
		}
		if file.LastEntryID < prevLastEntryID {
			return fmt.Errorf("lastEntryID for datafile %d is less than previous file lastEntryID: %s < %s", i, file.LastEntryID, prevLastEntryID)
		}
		prevLastEntryID = file.LastEntryID
	}

	// check that the number of entries is right
	if len(allEntriesMap) != len(expectedEntriesMap) {
		return fmt.Errorf("expected %d total entries, got %d", len(expectedEntriesMap), len(allEntriesMap))
	}
	if !reflect.DeepEqual(expectedEntriesMap, allEntriesMap) {
		return fmt.Errorf("expected entries don't match current entries")
	}

	return nil
}
