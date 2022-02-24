package common

import "context"

type ContextKey int

const (
	ContextKeyUserID ContextKey = iota
	ContextKeyUsername
	ContextKeyUserAdmin
)

func CurrentUserID(ctx context.Context) string {
	userIDVal := ctx.Value(ContextKeyUserID)
	if userIDVal == nil {
		return ""
	}
	return userIDVal.(string)
}

func IsUserLogged(ctx context.Context) bool {
	return ctx.Value(ContextKeyUserID) != nil
}

func IsUserAdmin(ctx context.Context) bool {
	isAdmin := false
	isAdminVal := ctx.Value(ContextKeyUserAdmin)
	if isAdminVal != nil {
		isAdmin = isAdminVal.(bool)
	}
	return isAdmin
}

func IsUserLoggedOrAdmin(ctx context.Context) bool {
	return IsUserLogged(ctx) || IsUserAdmin(ctx)
}
