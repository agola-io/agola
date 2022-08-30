package objects

import (
	idb "agola.io/agola/internal/db"
)

var ObjectsInfo = []idb.ObjectInfo{
	{Name: "RemoteSource", Table: "remotesource"},
	{Name: "User", Table: "user_t"},
	{Name: "UserToken", Table: "usertoken"},
	{Name: "LinkedAccount", Table: "linkedaccount"},
	{Name: "Organization", Table: "org"},
	{Name: "OrganizationMember", Table: "orgmember"},
	{Name: "ProjectGroup", Table: "projectgroup"},
	{Name: "Project", Table: "project"},
	{Name: "Secret", Table: "secret"},
	{Name: "Variable", Table: "variable"},
}
