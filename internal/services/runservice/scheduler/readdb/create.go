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
