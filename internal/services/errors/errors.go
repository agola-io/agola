package errors

import (
	"agola.io/agola/internal/util"
	apierrors "agola.io/agola/services/gateway/api/errors"
)

func detailedErrorOption(code util.ErrorCode) util.APIErrorOption {
	return util.WithAPIErrorDetailedError(util.NewAPIDetailedError(code))
}

func InvalidStartSequence() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidStartSequence)
}

func InvalidLimit() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidLimit)
}

func InvalidSortDirection() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidSortDirection)
}

func InvalidVisibility() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidVisibility)
}

func InvalidRole() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRole)
}

func InvalidPath() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidPath)
}

func InvalidRef() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRef)
}

func UserDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeUserDoesNotExist)
}

func UserAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeUserAlreadyExists)
}

func InvalidUserName() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidUserName)
}

func UserTokenDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeUserTokenDoesNotExist)
}

func UserTokenAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeUserTokenAlreadyExists)
}

func ParentProjectGroupDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeParentProjectGroupDoesNotExist)
}

func ProjectGroupDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeProjectGroupDoesNotExist)
}

func ProjectGroupAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeProjectGroupAlreadyExists)
}

func InvalidProjectGroupName() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidProjectGroupName)
}

func ProjectDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeProjectDoesNotExist)
}

func ProjectAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeProjectAlreadyExists)
}

func InvalidProjectName() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidProjectName)
}

func RemoteSourceDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRemoteSourceDoesNotExist)
}

func RemoteSourceAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRemoteSourceAlreadyExists)
}

func InvalidRemoteSourceName() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRemoteSourceName)
}

func InvalidRemoteSourceType() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRemoteSourceType)
}

func InvalidRemoteSourceAuthType() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRemoteSourceAuthType)
}

func InvalidRemoteSourceAPIURL() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRemoteSourceAPIURL)
}

func InvalidOauth2ClientID() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidOauth2ClientID)
}

func InvalidOauth2ClientSecret() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidOauth2ClientSecret)
}

func LinkedAccountDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeLinkedAccountDoesNotExist)
}

func LinkedAccountAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeLinkedAccountAlreadyExists)
}

func InvalidRepoPath() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRepoPath)
}

func CannotSetMembersCanPerformRunActionsOnUserProject() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeCannotSetMembersCanPerformRunActionsOnUserProject)
}

func SecretDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeSecretDoesNotExist)
}

func SecretAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeSecretAlreadyExists)
}

func InvalidSecretName() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidSecretName)
}

func InvalidSecretType() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidSecretType)
}

func InvalidSecretData() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidSecretData)
}

func VariableDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeVariableDoesNotExist)
}

func VariableAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeVariableAlreadyExists)
}

func InvalidVariableName() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidVariableName)
}

func InvalidVariableValues() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidVariableValues)
}

func CreatorUserDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeCreatorUserDoesNotExist)
}

func OrganizationDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeOrganizationDoesNotExist)
}

func OrganizationAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeOrganizationAlreadyExists)
}

func InvalidOrganizationName() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidOrganizationName)
}

func OrgMemberDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeOrgMemberDoesNotExist)
}

func InvitationDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvitationDoesNotExist)
}

func InvitationAlreadyExists() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvitationAlreadyExists)
}

func CannotAddUserToOrganization() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeCannotAddUserToOrganization)
}

func CannotCreateInvitation() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeCannotCreateInvitation)
}

func InvalidRunGroup() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRunGroup)
}

func InvalidRunNumber() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRunNumber)
}

func InvalidRunTaskStepNumber() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidRunTaskStepNumber)
}

func RunDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunDoesNotExist)
}

func RunTaskDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunTaskDoesNotExist)
}

func RunTaskStepDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunTaskStepDoesNotExist)
}

func RunCannotBeRestarted() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunCannotBeRestarted)
}

func RunTaskNotWaitingApproval() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunTaskNotWaitingApproval)
}

func RunTaskAlreadyApproved() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunTaskAlreadyApproved)
}

func InvalidDeliveryStatus() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeInvalidDeliveryStatus)
}

func CommitStatusDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeCommitStatusDoesNotExist)
}

func CommitStatusDeliveryDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeCommitStatusDeliveryDoesNotExist)
}

func CommitStatusDeliveryAlreadyInProgress() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeCommitStatusDeliveryAlreadyInProgress)
}

func RunWebhookDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunWebhookDoesNotExist)
}

func RunWebhookDeliveryDoesNotExist() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunWebhookDeliveryDoesNotExist)
}

func RunWebhookDeliveryAlreadyInProgress() util.APIErrorOption {
	return detailedErrorOption(apierrors.ErrorCodeRunWebhookDeliveryAlreadyInProgress)
}
