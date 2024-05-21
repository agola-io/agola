package util

import "context"

// ContextCanceled returns whether a context is canceled.
func ContextCanceled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
