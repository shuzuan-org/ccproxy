package admin

import "context"

// AdminAuthInfo carries the authenticated admin/user identity through request context.
type AdminAuthInfo struct {
	Username string // "admin" or api_key.name
	IsAdmin  bool
}

type adminAuthKey struct{}

// GetAdminAuth extracts AdminAuthInfo from the request context.
// Returns nil if no auth info is present.
func GetAdminAuth(ctx context.Context) *AdminAuthInfo {
	info, _ := ctx.Value(adminAuthKey{}).(*AdminAuthInfo)
	return info
}

// WithAdminAuth returns a new context carrying the given AdminAuthInfo.
func WithAdminAuth(ctx context.Context, info *AdminAuthInfo) context.Context {
	return context.WithValue(ctx, adminAuthKey{}, info)
}
