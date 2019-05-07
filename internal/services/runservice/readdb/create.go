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
	"create table revision (revision bigint, PRIMARY KEY(revision))",

	"create table run (id varchar, grouppath varchar, phase varchar, PRIMARY KEY (id, grouppath, phase))",

	"create table rundata (id varchar, data bytea, PRIMARY KEY (id))",

	"create table runevent (sequence varchar, data bytea, PRIMARY KEY (sequence))",

	// changegrouprevision stores the current revision of the changegroup for optimistic locking
	"create table changegrouprevision (id varchar, revision varchar, PRIMARY KEY (id, revision))",

	// objectstorage
	"create table revision_ost (revision bigint, PRIMARY KEY(revision))",

	// committedwalsequence stores the last committed wal sequence
	"create table committedwalsequence_ost (seq varchar, PRIMARY KEY (seq))",

	"create table changegrouprevision_ost (id varchar, revision varchar, PRIMARY KEY (id, revision))",

	"create table run_ost (id varchar, grouppath varchar, phase varchar, PRIMARY KEY (id, grouppath, phase))",

	"create table rundata_ost (id varchar, data bytea, PRIMARY KEY (id))",

	"create table runcounter_ost (groupid varchar, counter bigint, PRIMARY KEY (groupid))",
}
