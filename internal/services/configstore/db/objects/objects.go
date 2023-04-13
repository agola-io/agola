package objects

import (
	"agola.io/agola/internal/sqlg"
)

const (
	Version = uint(2)
)

const TypesImport = "agola.io/agola/services/configstore/types"

var AdditionalImports = []string{"time"}

var ObjectsInfo = []sqlg.ObjectInfo{
	{Name: "RemoteSource", Table: "remotesource",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "APIURL", Type: "string"},
			{Name: "SkipVerify", Type: "bool"},
			{Name: "Type", Type: "types.RemoteSourceType", SQLType: "varchar"},
			{Name: "AuthType", Type: "types.RemoteSourceAuthType", SQLType: "varchar"},
			{Name: "Oauth2ClientID", Type: "string"},
			{Name: "Oauth2ClientSecret", Type: "string"},
			{Name: "SSHHostKey", Type: "string"},
			{Name: "SkipSSHHostKeyCheck", Type: "bool"},
			{Name: "RegistrationEnabled", Type: "bool"},
			{Name: "LoginEnabled", Type: "bool"},
		},
	},
	{Name: "User", Table: "user_t",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Secret", Type: "string"},
			{Name: "Admin", Type: "bool"},
		},
	},
	{Name: "UserToken", Table: "usertoken",
		Fields: []sqlg.ObjectField{
			{Name: "UserID", Type: "string"},
			{Name: "Name", Type: "string"},
			{Name: "Value", Type: "string"},
		},
		Constraints: []string{
			"foreign key (user_id) references user_t(id)",
		},
	},
	{Name: "LinkedAccount", Table: "linkedaccount",
		Fields: []sqlg.ObjectField{
			{Name: "UserID", Type: "string"},
			{Name: "RemoteUserID", Type: "string"},
			{Name: "RemoteUserName", Type: "string"},
			{Name: "RemoteUserAvatarURL", Type: "string"},
			{Name: "RemoteSourceID", Type: "string"},
			{Name: "UserAccessToken", Type: "string"},
			{Name: "Oauth2AccessToken", Type: "string"},
			{Name: "Oauth2RefreshToken", Type: "string"},
			{Name: "Oauth2AccessTokenExpiresAt", Type: "time.Time"},
		},
		Constraints: []string{
			"foreign key (user_id) references user_t(id)",
			"foreign key (remote_source_id) references remotesource(id)",
		},
	},
	{Name: "Organization", Table: "organization",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Visibility", Type: "types.Visibility", SQLType: "varchar"},
			{Name: "CreatorUserID", Type: "string"},
		},
	},
	{Name: "OrganizationMember", Table: "orgmember",
		Fields: []sqlg.ObjectField{
			{Name: "OrganizationID", Type: "string"},
			{Name: "UserID", Type: "string"},
			{Name: "MemberRole", Type: "types.MemberRole", SQLType: "varchar"},
		},
		Constraints: []string{
			"foreign key (organization_id) references organization(id)",
			"foreign key (user_id) references user_t(id)",
		},
	},
	{Name: "ProjectGroup", Table: "projectgroup",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Parent.Kind", ColName: "parent_kind", Type: "types.ObjectKind", SQLType: "varchar"},
			{Name: "Parent.ID", ColName: "parent_id", Type: "string"},
			{Name: "Visibility", Type: "types.Visibility", SQLType: "varchar"},
		},
	},
	{Name: "Project", Table: "project",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Parent.Kind", ColName: "parent_kind", Type: "types.ObjectKind", SQLType: "varchar"},
			{Name: "Parent.ID", ColName: "parent_id", Type: "string"},
			{Name: "Secret", Type: "string"},
			{Name: "Visibility", Type: "types.Visibility", SQLType: "varchar"},
			{Name: "RemoteRepositoryConfigType", Type: "types.RemoteRepositoryConfigType", SQLType: "varchar"},
			{Name: "RemoteSourceID", Type: "string"},
			{Name: "LinkedAccountID", Type: "string"},
			{Name: "RepositoryID", Type: "string"},
			{Name: "RepositoryPath", Type: "string"},
			{Name: "SSHPrivateKey", Type: "string"},
			{Name: "SkipSSHHostKeyCheck", Type: "bool"},
			{Name: "WebhookSecret", Type: "string"},
			{Name: "PassVarsToForkedPR", Type: "bool"},
			{Name: "DefaultBranch", Type: "string"},
		},
	},
	{Name: "Secret", Table: "secret",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Parent.Kind", ColName: "parent_kind", Type: "types.ObjectKind", SQLType: "varchar"},
			{Name: "Parent.ID", ColName: "parent_id", Type: "string"},
			{Name: "Type", Type: "types.SecretType", SQLType: "varchar"},
			{Name: "Data", Type: "map[string]string", JSON: true},
			{Name: "SecretProviderID", Type: "string"},
			{Name: "Path", Type: "string"},
		},
	},
	{Name: "Variable", Table: "variable",
		Fields: []sqlg.ObjectField{
			{Name: "Name", Type: "string"},
			{Name: "Parent.Kind", ColName: "parent_kind", Type: "types.ObjectKind", SQLType: "varchar"},
			{Name: "Parent.ID", ColName: "parent_id", Type: "string"},
			{Name: "Values", ColName: "variable_values", Type: "[]types.VariableValue", JSON: true},
		},
	},
	{Name: "OrgInvitation", Table: "orginvitation",
		Fields: []sqlg.ObjectField{
			{Name: "UserID", Type: "string"},
			{Name: "OrganizationID", Type: "string"},
			{Name: "Role", Type: "types.MemberRole", SQLType: "varchar"},
		},
		Constraints: []string{
			"foreign key (user_id) references user_t(id)",
			"foreign key (organization_id) references organization(id)",
		},
	},
}
