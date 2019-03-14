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

	// committedwalsequence stores the last committed wal sequence
	"create table committedwalsequence (seq varchar, PRIMARY KEY (seq))",

	// changegrouprevision stores the current revision of the changegroup for optimistic locking
	"create table changegrouprevision (id varchar, revision varchar, PRIMARY KEY (id, revision))",

	"create table projectgroup (id uuid, name varchar, parentid varchar, data bytea, PRIMARY KEY (id))",
	"create index projectgroup_name on projectgroup(name)",

	"create table project (id uuid, name varchar, parentid varchar, data bytea, PRIMARY KEY (id))",
	"create index project_name on project(name)",

	"create table user (id uuid, name varchar, data bytea, PRIMARY KEY (id))",
	"create index user_name on user(name)",
	"create table user_token (tokenvalue varchar, userid uuid, PRIMARY KEY (tokenvalue, userid))",

	"create table org (id uuid, name varchar, data bytea, PRIMARY KEY (id))",
	"create index org_name on org(name)",

	"create table remotesource (id uuid, name varchar, data bytea, PRIMARY KEY (id))",

	"create table linkedaccount_user (id uuid, remotesourceid uuid, userid uuid, remoteuserid uuid, PRIMARY KEY (id), FOREIGN KEY(userid) REFERENCES user(id))",

	"create table linkedaccount_project (id uuid, projectid uuid, PRIMARY KEY (id), FOREIGN KEY(projectid) REFERENCES user(id))",

	"create table secret (id uuid, name varchar, containerid varchar, data bytea, PRIMARY KEY (id))",
	"create index secret_name on secret(name)",

	"create table variable (id uuid, name varchar, containerid varchar, data bytea, PRIMARY KEY (id))",
	"create index variable_name on variable(name)",
}
