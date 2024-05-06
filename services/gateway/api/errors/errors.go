package errors

import "agola.io/agola/internal/util"

const (
	ErrorCodeInvalidStartSequence util.ErrorCode = "invalidStartSequence"
	ErrorCodeInvalidLimit         util.ErrorCode = "invalidLimit"
	ErrorCodeInvalidSortDirection util.ErrorCode = "invalidSortDirection"

	ErrorCodeInvalidVisibility util.ErrorCode = "invalidVisibility"

	ErrorCodeInvalidRole util.ErrorCode = "invalidRole"

	ErrorCodeInvalidPath util.ErrorCode = "invalidPath"
	ErrorCodeInvalidRef  util.ErrorCode = "invalidRef"

	ErrorCodeUserDoesNotExist  util.ErrorCode = "userDoesNotExist"
	ErrorCodeUserAlreadyExists util.ErrorCode = "userAlreadyExists"
	ErrorCodeInvalidUserName   util.ErrorCode = "invalidUserName"

	ErrorCodeUserTokenDoesNotExist  util.ErrorCode = "userTokenDoesNotExist"
	ErrorCodeUserTokenAlreadyExists util.ErrorCode = "userTokenAlreadyExists"

	ErrorCodeParentProjectGroupDoesNotExist util.ErrorCode = "parentProjectGroupDoesNotExist"

	ErrorCodeProjectGroupDoesNotExist  util.ErrorCode = "projectGroupDoesNotExist"
	ErrorCodeProjectGroupAlreadyExists util.ErrorCode = "projectGroupAlreadyExists"
	ErrorCodeInvalidProjectGroupName   util.ErrorCode = "invalidProjectGroupName"

	ErrorCodeProjectDoesNotExist                               util.ErrorCode = "projectDoesNotExist"
	ErrorCodeProjectAlreadyExists                              util.ErrorCode = "projectAlreadyExists"
	ErrorCodeInvalidProjectName                                util.ErrorCode = "invalidProjectName"
	ErrorCodeCannotSetMembersCanPerformRunActionsOnUserProject util.ErrorCode = "cannotSetMembersCanPerformRunActionsOnUserProject"

	ErrorCodeRemoteSourceDoesNotExist    util.ErrorCode = "remoteSourceDoesNotExist"
	ErrorCodeRemoteSourceAlreadyExists   util.ErrorCode = "remoteSourceAlreadyExists"
	ErrorCodeInvalidRemoteSourceName     util.ErrorCode = "invalidRemoteSourceName"
	ErrorCodeInvalidRemoteSourceType     util.ErrorCode = "invalidRemoteSourceType"
	ErrorCodeInvalidRemoteSourceAuthType util.ErrorCode = "invalidRemoteSourceAuthType"
	ErrorCodeInvalidRemoteSourceAPIURL   util.ErrorCode = "invalidRemoteSourceAPIURL"
	ErrorCodeInvalidOauth2ClientID       util.ErrorCode = "invalidOauth2ClientID"
	ErrorCodeInvalidOauth2ClientSecret   util.ErrorCode = "invalidOauth2ClientSecret"

	ErrorCodeLinkedAccountDoesNotExist  util.ErrorCode = "linkedAccountDoesNotExist"
	ErrorCodeLinkedAccountAlreadyExists util.ErrorCode = "linkedAccountAlreadyExists"

	ErrorCodeInvalidRepoPath util.ErrorCode = "invalidRepoPath"

	ErrorCodeSecretDoesNotExist  util.ErrorCode = "secretDoesNotExist"
	ErrorCodeSecretAlreadyExists util.ErrorCode = "secretAlreadyExists"
	ErrorCodeInvalidSecretName   util.ErrorCode = "invalidSecretName"
	ErrorCodeInvalidSecretType   util.ErrorCode = "invalidSecretType"
	ErrorCodeInvalidSecretData   util.ErrorCode = "invalidSecretData"

	ErrorCodeVariableDoesNotExist  util.ErrorCode = "variableDoesNotExist"
	ErrorCodeVariableAlreadyExists util.ErrorCode = "variableAlreadyExists"
	ErrorCodeInvalidVariableName   util.ErrorCode = "invalidVariableName"
	ErrorCodeInvalidVariableValues util.ErrorCode = "invalidVariableValues"

	ErrorCodeCreatorUserDoesNotExist util.ErrorCode = "creatorUserDoesNotExist"

	ErrorCodeOrganizationDoesNotExist  util.ErrorCode = "organizationDoesNotExist"
	ErrorCodeOrganizationAlreadyExists util.ErrorCode = "organizationAlreadyExists"
	ErrorCodeInvalidOrganizationName   util.ErrorCode = "invalidOrganizationName"

	ErrorCodeOrgMemberDoesNotExist util.ErrorCode = "orgMemberDoesNotExist"

	ErrorCodeInvitationDoesNotExist  util.ErrorCode = "invitationDoesNotExist"
	ErrorCodeInvitationAlreadyExists util.ErrorCode = "invitationAlreadyExists"

	ErrorCodeCannotAddUserToOrganization util.ErrorCode = "cannotAddUserToOrganization"
	ErrorCodeCannotCreateInvitation      util.ErrorCode = "cannotCreateInvitation"

	ErrorCodeInvalidRunGroup           util.ErrorCode = "invalidRunGroup"
	ErrorCodeInvalidRunNumber          util.ErrorCode = "invalidRunNumber"
	ErrorCodeInvalidRunTaskStepNumber  util.ErrorCode = "invalidRunTaskStepNumber"
	ErrorCodeRunDoesNotExist           util.ErrorCode = "runDoesNotExist"
	ErrorCodeRunTaskDoesNotExist       util.ErrorCode = "runTaskDoesNotExist"
	ErrorCodeRunTaskStepDoesNotExist   util.ErrorCode = "runTaskStepDoesNotExist"
	ErrorCodeRunCannotBeRestarted      util.ErrorCode = "runCannotBeRestarted"
	ErrorCodeRunTaskNotWaitingApproval util.ErrorCode = "runTaskNotWaitingApproval"
	ErrorCodeRunTaskAlreadyApproved    util.ErrorCode = "runTaskAlreadyApproved"

	ErrorCodeInvalidDeliveryStatus util.ErrorCode = "invalidDeliveryStatus"

	ErrorCodeCommitStatusDoesNotExist              util.ErrorCode = "commitStatusDoesNotExist"
	ErrorCodeCommitStatusDeliveryDoesNotExist      util.ErrorCode = "commitStatusDeliveryDoesNotExist"
	ErrorCodeCommitStatusDeliveryAlreadyInProgress util.ErrorCode = "commitStatusDeliveryAlreadyInProgress"

	ErrorCodeRunWebhookDoesNotExist              util.ErrorCode = "runWebhookDoesNotExist"
	ErrorCodeRunWebhookDeliveryDoesNotExist      util.ErrorCode = "runWebhookDeliveryDoesNotExist"
	ErrorCodeRunWebhookDeliveryAlreadyInProgress util.ErrorCode = "runWebhookDeliveryAlreadyInProgress"
)
