package loadbalancer

import "bytes"

const (
	PlatformBanReasonForbidden            = "platform_forbidden"
	PlatformBanReasonOAuthNotAllowed      = "platform_oauth_not_allowed"
	PlatformBanReasonOrganizationDisabled = "platform_organization_disabled"
	legacyBanReasonForbidden              = "forbidden"
)

func IsPlatformBanReason(reason string) bool {
	switch reason {
	case PlatformBanReasonForbidden,
		PlatformBanReasonOAuthNotAllowed,
		PlatformBanReasonOrganizationDisabled,
		legacyBanReasonForbidden:
		return true
	default:
		return false
	}
}

func DetectPlatformBan(statusCode int, body []byte) (string, bool) {
	message := bytes.ToLower(body)
	switch statusCode {
	case 400, 403:
		if bytes.Contains(message, []byte("oauth")) && bytes.Contains(message, []byte("not allowed")) {
			return PlatformBanReasonOAuthNotAllowed, true
		}
		if bytes.Contains(message, []byte("organization disabled")) {
			return PlatformBanReasonOrganizationDisabled, true
		}
		if statusCode == 403 {
			return PlatformBanReasonForbidden, true
		}
	}

	return "", false
}
