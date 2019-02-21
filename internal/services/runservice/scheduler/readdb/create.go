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

	"create table run (id varchar, data bytea, phase varchar, PRIMARY KEY (id))",
	"create index run_phase on run(phase)",

	// rungroup stores the groups associated to a run
	"create table rungroup (runid varchar, grouppath varchar, PRIMARY KEY (runid, grouppath), FOREIGN KEY(runid) REFERENCES run(id) ON DELETE CASCADE)",
	"create index rungroup_grouppath on rungroup(grouppath)",

	"create table runevent (sequence varchar, data bytea, PRIMARY KEY (sequence))",

	// changegrouprevision stores the current revision of the changegroup for optimistic locking
	"create table changegrouprevision (id varchar, revision varchar, PRIMARY KEY (id, revision))",

	// LTS
	"create table run_lts (id varchar, data bytea, phase varchar, PRIMARY KEY (id))",
	"create index run_lts_phase on run_lts(phase)",

	// rungroup stores the groups associated to a run
	"create table rungroup_lts (runid varchar, grouppath varchar, PRIMARY KEY (runid, grouppath), FOREIGN KEY(runid) REFERENCES run_lts(id) ON DELETE CASCADE)",
	"create index rungroup_lts_grouppath on rungroup_lts(grouppath)",
}
