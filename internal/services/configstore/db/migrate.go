package db

import (
	"fmt"

	sq "github.com/huandu/go-sqlbuilder"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

func (d *DB) MigrateFuncs() map[uint]sqlg.MigrateFunc {
	return map[uint]sqlg.MigrateFunc{
		2: d.migrateV2,
		3: d.migrateV3,
	}
}

func (d *DB) cleanUnreferenced(tx *sql.Tx, t, tc, jt, jtc string) error {
	iq := sq.NewSelectBuilder().Select(fmt.Sprintf("%s.%s", t, "id")).From(t)
	iq.JoinWithOption(sq.LeftJoin, jt, fmt.Sprintf("%s.%s = %s.%s", t, tc, jt, jtc)).Where(iq.IsNull(fmt.Sprintf("%s.%s", jt, jtc)))

	q := sq.NewDeleteBuilder().DeleteFrom(t)
	q.Where(q.In(fmt.Sprintf("%s.%s", t, "id"), iq))
	if _, err := d.exec(tx, q); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (d *DB) migrateV2(tx *sql.Tx) error {
	var ddlPostgres = []string{
		"ALTER TABLE usertoken ADD CONSTRAINT usertoken_user_id_fkey FOREIGN KEY (user_id) REFERENCES user_t(id)",
		"ALTER TABLE linkedaccount ADD CONSTRAINT linkedaccount_user_id_fkey FOREIGN KEY (user_id) REFERENCES user_t(id)",
		"ALTER TABLE linkedaccount ADD CONSTRAINT linkedaccount_remote_source_id_fkey FOREIGN KEY (remote_source_id) REFERENCES remotesource(id)",
		"ALTER TABLE orginvitation ADD CONSTRAINT orginvitation_user_id_fkey FOREIGN KEY (user_id) REFERENCES user_t(id)",
		"ALTER TABLE orginvitation ADD CONSTRAINT orginvitation_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES organization(id)",
		"ALTER TABLE orgmember ADD CONSTRAINT orgmember_user_id_fkey FOREIGN KEY (user_id) REFERENCES user_t(id)",
		"ALTER TABLE orgmember ADD CONSTRAINT orgmember_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES organization(id)",
	}

	var ddlSqlite3 = []string{
		"CREATE TABLE new_usertoken (id varchar NOT NULL, revision bigint NOT NULL, creation_time timestamp NOT NULL, update_time timestamp NOT NULL, user_id varchar NOT NULL, name varchar NOT NULL, value varchar NOT NULL, PRIMARY KEY (id), foreign key (user_id) references user_t(id))",
		"INSERT INTO new_usertoken SELECT * FROM usertoken",
		"DROP TABLE usertoken",
		"ALTER TABLE new_usertoken RENAME TO usertoken",

		"CREATE TABLE new_linkedaccount (id varchar NOT NULL, revision bigint NOT NULL, creation_time timestamp NOT NULL, update_time timestamp NOT NULL, user_id varchar NOT NULL, remote_user_id varchar NOT NULL, remote_user_name varchar NOT NULL, remote_user_avatar_url varchar NOT NULL, remote_source_id varchar NOT NULL, user_access_token varchar NOT NULL, oauth2_access_token varchar NOT NULL, oauth2_refresh_token varchar NOT NULL, oauth2_access_token_expires_at timestamp NOT NULL, PRIMARY KEY (id), foreign key (user_id) references user_t(id), foreign key (remote_source_id) references remotesource(id))",
		"INSERT INTO new_linkedaccount SELECT * FROM linkedaccount",
		"DROP TABLE linkedaccount",
		"ALTER TABLE new_linkedaccount RENAME TO linkedaccount",

		"CREATE TABLE new_orgmember (id varchar NOT NULL, revision bigint NOT NULL, creation_time timestamp NOT NULL, update_time timestamp NOT NULL, organization_id varchar NOT NULL, user_id varchar NOT NULL, member_role varchar NOT NULL, PRIMARY KEY (id), foreign key (organization_id) references organization(id), foreign key (user_id) references user_t(id))",
		"INSERT INTO new_orgmember SELECT * FROM orgmember",
		"DROP TABLE orgmember",
		"ALTER TABLE new_orgmember RENAME TO orgmember",

		"CREATE TABLE new_orginvitation (id varchar NOT NULL, revision bigint NOT NULL, creation_time timestamp NOT NULL, update_time timestamp NOT NULL, user_id varchar NOT NULL, organization_id varchar NOT NULL, role varchar NOT NULL, PRIMARY KEY (id), foreign key (user_id) references user_t(id), foreign key (organization_id) references organization(id))",
		"INSERT INTO new_orginvitation SELECT * FROM orginvitation",
		"DROP TABLE orginvitation",
		"ALTER TABLE new_orginvitation RENAME TO orginvitation",
	}

	var stmts []string
	switch d.sdb.Type() {
	case sql.Postgres:
		stmts = ddlPostgres
	case sql.Sqlite3:
		stmts = ddlSqlite3
	}

	if d.sdb.Type() == sql.Postgres {
		// defer constraints for postgres
		if _, err := tx.Exec("SET CONSTRAINTS ALL DEFERRED"); err != nil {
			return errors.WithStack(err)
		}
	}

	// clean broken references
	if err := d.cleanUnreferenced(tx, "usertoken", "user_id", "user_t", "id"); err != nil {
		return errors.WithStack(err)
	}

	if err := d.cleanUnreferenced(tx, "orgmember", "user_id", "user_t", "id"); err != nil {
		return errors.WithStack(err)
	}
	if err := d.cleanUnreferenced(tx, "orgmember", "organization_id", "organization", "id"); err != nil {
		return errors.WithStack(err)
	}

	if err := d.cleanUnreferenced(tx, "linkedaccount", "user_id", "user_t", "id"); err != nil {
		return errors.WithStack(err)
	}
	if err := d.cleanUnreferenced(tx, "linkedaccount", "remote_source_id", "remotesource", "id"); err != nil {
		return errors.WithStack(err)
	}

	if err := d.cleanUnreferenced(tx, "orginvitation", "user_id", "user_t", "id"); err != nil {
		return errors.WithStack(err)
	}
	if err := d.cleanUnreferenced(tx, "orginvitation", "organization_id", "organization", "id"); err != nil {
		return errors.WithStack(err)
	}

	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (d *DB) migrateV3(tx *sql.Tx) error {
	var ddlPostgres = []string{
		"ALTER TABLE project ADD COLUMN members_can_perform_run_actions boolean",
		"UPDATE project SET members_can_perform_run_actions=false",
		"ALTER TABLE project ALTER COLUMN members_can_perform_run_actions SET NOT NULL",
	}

	var ddlSqlite3 = []string{
		"CREATE TABLE new_project (id varchar NOT NULL, revision bigint NOT NULL, creation_time timestamp NOT NULL, update_time timestamp NOT NULL, name varchar NOT NULL, parent_kind varchar NOT NULL, parent_id varchar NOT NULL, secret varchar NOT NULL, visibility varchar NOT NULL, remote_repository_config_type varchar NOT NULL, remote_source_id varchar NOT NULL, linked_account_id varchar NOT NULL, repository_id varchar NOT NULL, repository_path varchar NOT NULL, ssh_private_key varchar NOT NULL, skip_ssh_host_key_check integer NOT NULL, webhook_secret varchar NOT NULL, pass_vars_to_forked_pr integer NOT NULL, default_branch varchar NOT NULL, members_can_perform_run_actions integer NOT NULL, PRIMARY KEY (id))",
		"INSERT INTO new_project SELECT *, false AS members_can_perform_run_actions FROM project",
		"DROP TABLE project",
		"ALTER TABLE new_project RENAME TO project",
	}

	var stmts []string
	switch d.sdb.Type() {
	case sql.Postgres:
		stmts = ddlPostgres
	case sql.Sqlite3:
		stmts = ddlSqlite3
	}

	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
