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

package readdb

var Stmts = []string{
	// last processed etcd event revision
	//"create table revision (clusterid varchar, revision bigint, PRIMARY KEY(revision))",
	"create table revision (revision bigint, PRIMARY KEY(revision))",

	"create table run (id varchar, grouppath varchar, phase varchar, PRIMARY KEY (id, grouppath, phase))",

	"create table rundata (id varchar, data bytea, PRIMARY KEY (id))",

	"create table runevent (sequence varchar, data bytea, PRIMARY KEY (sequence))",

	// changegrouprevision stores the current revision of the changegroup for optimistic locking
	"create table changegrouprevision (id varchar, revision varchar, PRIMARY KEY (id, revision))",

	// LTS
	"create table revision_lts (revision bigint, PRIMARY KEY(revision))",

	// committedwalsequence stores the last committed wal sequence
	"create table committedwalsequence_lts (seq varchar, PRIMARY KEY (seq))",

	"create table changegrouprevision_lts (id varchar, revision varchar, PRIMARY KEY (id, revision))",

	"create table run_lts (id varchar, grouppath varchar, phase varchar, PRIMARY KEY (id, grouppath, phase))",

	"create table rundata_lts (id varchar, data bytea, PRIMARY KEY (id))",

	"create table runcounter_lts (groupid varchar, counter bigint, PRIMARY KEY (groupid))",
}
