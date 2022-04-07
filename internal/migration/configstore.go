package migration

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	idb "agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/lock"
	oldcstypes "agola.io/agola/internal/migration/configstore/types"
	ndb "agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/configstore/types"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
)

func MigrateConfigStore(ctx context.Context, r io.Reader, w io.Writer) error {
	ll := lock.NewLocalLocks()
	lf := lock.NewLocalLockFactory(ll)

	dir, err := ioutil.TempDir("", "agolamigration")
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	newDBPath := filepath.Join(dir, "newdb")
	os.RemoveAll(newDBPath)

	newsdb, err := sql.NewDB(sql.Sqlite3, newDBPath)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	defer newsdb.Close()

	newd, err := ndb.NewDB(log.Logger, newsdb)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}

	if err := idb.Setup(ctx, log.Logger, newd, lf); err != nil {
		return errors.Wrap(err, "create db error")
	}

	br := bufio.NewReader(r)
	dec := json.NewDecoder(br)

	newTx, err := newsdb.NewTx(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	for {
		var de *DataEntry

		err := dec.Decode(&de)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.WithStack(err)
		}

		switch de.DataType {
		case "user":
			var oldUser *oldcstypes.User

			if err := json.Unmarshal(de.Data, &oldUser); err != nil {
				return errors.WithStack(err)
			}

			oldUserj, _ := json.Marshal(oldUser)
			log.Debug().Msgf("oldUser: %s", oldUserj)

			user := types.NewUser()
			user.ID = oldUser.ID
			user.Name = oldUser.Name
			user.Secret = oldUser.Secret
			// user.LinkedAccounts = oldUser.LinkedAccounts
			// user.Tokens = oldUser.Tokens
			user.Admin = oldUser.Admin

			if err := newd.InsertUser(newTx, user); err != nil {
				return errors.WithStack(err)
			}

			for _, oldLA := range oldUser.LinkedAccounts {
				la := types.NewLinkedAccount()
				// reuse old linked account id since it's referenced by project
				la.ID = oldLA.ID
				la.UserID = user.ID

				la.RemoteUserID = oldLA.RemoteUserID
				la.RemoteUserName = oldLA.RemoteUserName
				la.RemoteUserAvatarURL = oldLA.RemoteUserAvatarURL
				la.RemoteSourceID = oldLA.RemoteSourceID
				la.UserAccessToken = oldLA.UserAccessToken
				la.Oauth2AccessToken = oldLA.Oauth2AccessToken
				la.Oauth2RefreshToken = oldLA.Oauth2RefreshToken
				la.Oauth2AccessTokenExpiresAt = oldLA.Oauth2AccessTokenExpiresAt

				if err := newd.InsertLinkedAccount(newTx, la); err != nil {
					return errors.WithStack(err)
				}
			}

			for oldTokenName, oldTokenValue := range oldUser.Tokens {
				userToken := types.NewUserToken()
				// reuse old linked account id since it's referenced by project
				userToken.UserID = user.ID
				userToken.Name = oldTokenName
				userToken.Value = oldTokenValue

				if err := newd.InsertUserToken(newTx, userToken); err != nil {
					return errors.WithStack(err)
				}
			}

		case "org":
			var oldOrg *oldcstypes.Organization

			if err := json.Unmarshal(de.Data, &oldOrg); err != nil {
				return errors.WithStack(err)
			}

			oldOrgj, _ := json.Marshal(oldOrg)
			log.Debug().Msgf("oldOrg: %s", oldOrgj)

			org := types.NewOrganization()
			org.ID = oldOrg.ID
			org.Name = oldOrg.Name
			org.Visibility = types.Visibility(oldOrg.Visibility)
			org.CreatorUserID = oldOrg.CreatorUserID
			org.CreationTime = oldOrg.CreatedAt

			if err := newd.InsertOrganization(newTx, org); err != nil {
				return errors.WithStack(err)
			}

		case "orgmember":
			var oldOrgMember *oldcstypes.OrganizationMember

			if err := json.Unmarshal(de.Data, &oldOrgMember); err != nil {
				return errors.WithStack(err)
			}

			oldOrgMemberj, _ := json.Marshal(oldOrgMember)
			log.Debug().Msgf("oldOrgMember: %s", oldOrgMemberj)

			orgMember := types.NewOrganizationMember()
			orgMember.ID = oldOrgMember.ID
			orgMember.OrganizationID = oldOrgMember.OrganizationID
			orgMember.UserID = oldOrgMember.UserID
			orgMember.MemberRole = types.MemberRole(oldOrgMember.MemberRole)

			if err := newd.InsertOrganizationMember(newTx, orgMember); err != nil {
				return errors.WithStack(err)
			}

		case "projectgroup":
			var oldProjectGroup *oldcstypes.ProjectGroup

			if err := json.Unmarshal(de.Data, &oldProjectGroup); err != nil {
				return errors.WithStack(err)
			}

			oldProjectGroupj, _ := json.Marshal(oldProjectGroup)
			log.Debug().Msgf("oldProjectGroup: %s", oldProjectGroupj)

			projectGroup := types.NewProjectGroup()
			projectGroup.ID = oldProjectGroup.ID
			projectGroup.Name = oldProjectGroup.Name
			projectGroup.Parent = types.Parent{
				Kind: types.ObjectKind(oldProjectGroup.Parent.Type),
				ID:   oldProjectGroup.Parent.ID,
			}
			projectGroup.Visibility = types.Visibility(oldProjectGroup.Visibility)

			if err := newd.InsertProjectGroup(newTx, projectGroup); err != nil {
				return errors.WithStack(err)
			}

		case "project":
			var oldProject *oldcstypes.Project

			if err := json.Unmarshal(de.Data, &oldProject); err != nil {
				return errors.WithStack(err)
			}

			oldProjectj, _ := json.Marshal(oldProject)
			log.Debug().Msgf("oldProject: %s", oldProjectj)

			project := types.NewProject()
			project.ID = oldProject.ID
			project.Name = oldProject.Name
			project.Parent = types.Parent{
				Kind: types.ObjectKind(oldProject.Parent.Type),
				ID:   oldProject.Parent.ID,
			}
			project.Secret = oldProject.Secret
			project.Visibility = types.Visibility(oldProject.Visibility)

			project.RemoteRepositoryConfigType = types.RemoteRepositoryConfigType(oldProject.RemoteRepositoryConfigType)
			project.RemoteSourceID = oldProject.RemoteSourceID
			project.LinkedAccountID = oldProject.LinkedAccountID
			project.RepositoryID = oldProject.RepositoryID
			project.RepositoryPath = oldProject.RepositoryPath
			project.SSHPrivateKey = oldProject.SSHPrivateKey
			project.SkipSSHHostKeyCheck = oldProject.SkipSSHHostKeyCheck
			project.WebhookSecret = oldProject.WebhookSecret
			project.PassVarsToForkedPR = oldProject.PassVarsToForkedPR

			if err := newd.InsertProject(newTx, project); err != nil {
				return errors.WithStack(err)
			}

		case "remotesource":
			var oldRemoteSource *oldcstypes.RemoteSource

			if err := json.Unmarshal(de.Data, &oldRemoteSource); err != nil {
				return errors.WithStack(err)
			}

			oldRemoteSourcej, _ := json.Marshal(oldRemoteSource)
			log.Debug().Msgf("oldRemoteSource: %s", oldRemoteSourcej)

			remoteSource := types.NewRemoteSource()
			remoteSource.ID = oldRemoteSource.ID
			remoteSource.Name = oldRemoteSource.Name
			remoteSource.APIURL = oldRemoteSource.APIURL
			remoteSource.SkipVerify = oldRemoteSource.SkipVerify
			remoteSource.Type = types.RemoteSourceType(oldRemoteSource.Type)
			remoteSource.AuthType = types.RemoteSourceAuthType(oldRemoteSource.AuthType)
			remoteSource.Oauth2ClientID = oldRemoteSource.Oauth2ClientID
			remoteSource.Oauth2ClientSecret = oldRemoteSource.Oauth2ClientSecret
			remoteSource.SSHHostKey = oldRemoteSource.SSHHostKey
			remoteSource.SkipSSHHostKeyCheck = oldRemoteSource.SkipSSHHostKeyCheck
			remoteSource.RegistrationEnabled = oldRemoteSource.RegistrationEnabled
			remoteSource.LoginEnabled = oldRemoteSource.LoginEnabled

			if err := newd.InsertRemoteSource(newTx, remoteSource); err != nil {
				return errors.WithStack(err)
			}

		case "secret":
			var oldSecret *oldcstypes.Secret

			if err := json.Unmarshal(de.Data, &oldSecret); err != nil {
				return errors.WithStack(err)
			}

			oldSecretj, _ := json.Marshal(oldSecret)
			log.Debug().Msgf("oldSecret: %s", oldSecretj)

			secret := types.NewSecret()
			secret.ID = oldSecret.ID
			secret.Name = oldSecret.Name
			secret.Parent = types.Parent{
				Kind: types.ObjectKind(oldSecret.Parent.Type),
				ID:   oldSecret.Parent.ID,
			}
			secret.Type = types.SecretType(oldSecret.Type)
			secret.Data = oldSecret.Data
			secret.SecretProviderID = oldSecret.SecretProviderID
			secret.Path = oldSecret.Path

			if err := newd.InsertSecret(newTx, secret); err != nil {
				return errors.WithStack(err)
			}

		case "variable":
			var oldVariable *oldcstypes.Variable

			if err := json.Unmarshal(de.Data, &oldVariable); err != nil {
				return errors.WithStack(err)
			}

			oldVariablej, _ := json.Marshal(oldVariable)
			log.Debug().Msgf("oldVariable: %s", oldVariablej)

			variable := types.NewVariable()
			variable.ID = oldVariable.ID
			variable.Name = oldVariable.Name
			variable.Parent = types.Parent{
				Kind: types.ObjectKind(oldVariable.Parent.Type),
				ID:   oldVariable.Parent.ID,
			}

			if oldVariable.Values != nil {
				if err := mapstructure.Decode(oldVariable.Values, &variable.Values); err != nil {
					return errors.WithStack(err)
				}
			}

			if err := newd.InsertVariable(newTx, variable); err != nil {
				return errors.WithStack(err)
			}

		default:
			return errors.Errorf("unknown data type %q", de.DataType)
		}
	}

	if err := newTx.Commit(); err != nil {
		return errors.WithStack(err)
	}

	// Export new version
	if err := idb.Export(ctx, log.Logger, newd, w); err != nil {
		return errors.Wrap(err, "export db error")
	}

	return nil
}
