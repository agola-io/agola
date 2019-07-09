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
	"create table revision (revision bigint, PRIMARY KEY(revision))",

	// committedwalsequence stores the last committed wal sequence
	"create table committedwalsequence (seq varchar, PRIMARY KEY (seq))",

	// changegrouprevision stores the current revision of the changegroup for optimistic locking
	"create table changegrouprevision (id varchar, revision varchar, PRIMARY KEY (id, revision))",

	"create table projectgroup (id uuid, name varchar, parentid varchar, parenttype varchar, data bytea, PRIMARY KEY (id))",
	"create index projectgroup_name on projectgroup(name)",

	"create table project (id uuid, name varchar, parentid varchar, parenttype varchar, data bytea, PRIMARY KEY (id))",
	"create index project_name on project(name)",

	"create table user (id uuid, name varchar, data bytea, PRIMARY KEY (id))",
	"create index user_name on user(name)",
	"create table user_token (tokenvalue varchar, userid uuid, PRIMARY KEY (tokenvalue, userid))",

	"create table org (id uuid, name varchar, data bytea, PRIMARY KEY (id))",
	"create index org_name on org(name)",

	"create table orgmember (id uuid, orgid uuid, userid uuid, role varchar, data bytea, PRIMARY KEY (id))",
	"create index orgmember_role on orgmember(role)",
	"create index orgmember_orgid_userid on orgmember(orgid, userid)",

	"create table remotesource (id uuid, name varchar, data bytea, PRIMARY KEY (id))",

	"create table linkedaccount_user (id uuid, remotesourceid uuid, userid uuid, remoteuserid uuid, PRIMARY KEY (id), FOREIGN KEY(userid) REFERENCES user(id))",

	"create table linkedaccount_project (id uuid, projectid uuid, PRIMARY KEY (id), FOREIGN KEY(projectid) REFERENCES user(id))",

	"create table secret (id uuid, name varchar, parentid varchar, parenttype varchar, data bytea, PRIMARY KEY (id))",
	"create index secret_name on secret(name)",

	"create table variable (id uuid, name varchar, parentid varchar, parenttype varchar, data bytea, PRIMARY KEY (id))",
	"create index variable_name on variable(name)",
}
