package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
)

// SanitizeIncomingResponseType validates and returns a validated response type from a user request.
// It is used in the OAuth 2.0 authorization endpoint.
func SanitizeIncomingResponseType(responseType ResponseType) (ResponseType, error) {
	if _, registered := ResponseTypes[responseType]; !registered {
		return responseType, fmt.Errorf("unknown response type '%s'", responseType)
	}
	if responseType == ResponseTypeToken {
		return responseType, errors.New("only authorization codes and id tokens may be generated")
	}
	return responseType, nil
}

// SanitizeIncomingGrantType validates and returns a validated grant type from a user request.
// It is used in the OAuth 2.0 token endpoint.
func SanitizeIncomingGrantType(grantType GrantType) (GrantType, error) {
	if _, valid := GrantTypes[grantType]; !valid {
		return grantType, errors.New("only grant types 'authorization_code' and 'refresh_token' are supported")
	}
	if grantType != GrantTypeAuthorizationCode { // Value MUST be set to "authorization_code".
		return grantType, fmt.Errorf("expected 'grant_type' to be 'authorization_code', got '%s'", grantType)
	}
	return grantType, nil
}

// SanitizeIncomingRedirectURI parses, validates, and returns a validated redirect URI from a user request.
// It is used in the OAuth 2.0 authorization endpoint.
//
// It checks:
// 1. Redirect URI is a valid URL.
// 2. Redirect URI is an absolute URL.
// 3. If the Redirect URI is empty, provide in-place the first of the clients' registered Redirect URIs.
func SanitizeIncomingRedirectURI(client Client, redirectURI string) (*url.URL, string, error) {
	var parsed *url.URL

	if redirectURI != "" {
		var err error

		parsed, err = url.Parse(redirectURI)
		if err != nil {
			return nil, redirectURI, fmt.Errorf("bad redirect uri '%s': %w", redirectURI, err)
		}

		if !parsed.IsAbs() {
			return nil, redirectURI, fmt.Errorf("redirect uri '%s' must be absolute", redirectURI)
		}
	}

	if len(client.AllowedRedirectURIs) == 0 {
		return nil, redirectURI, errors.New("client has no redirect uri's registered")
	}

	if parsed == nil {
		var err error

		for allowedRedirectURI := range client.AllowedRedirectURIs {
			redirectURI = allowedRedirectURI

			parsed, err = url.Parse(redirectURI)
			if err != nil {
				return nil, redirectURI, fmt.Errorf("client-registered allowed redirect uri '%s' is not valid: %w", redirectURI, err)
			}

			if !parsed.IsAbs() {
				return nil, redirectURI, fmt.Errorf("client-registered redirect uri '%s' is not absolute", redirectURI)
			}

			break
		}
	} else {
		if _, allowed := client.AllowedRedirectURIs[redirectURI]; !allowed {
			return nil, redirectURI, fmt.Errorf("redirect uri '%s' is not authorized under client id '%s'", redirectURI, client.ID)
		}
	}

	return parsed, redirectURI, nil
}

// ValidateIncomingCodeChallengePKCE returns an error if the code challenge method is unknown or not allowed, if the
// client is a public client and a code challenge hasn't been provided, or if the code challenge is malformed.
// It is used in the OAuth 2.0 authorization endpoint.
func ValidateIncomingCodeChallengePKCE(client Client, codeChallenge string, codeChallengeMethod CodeChallengeMethod) error {
	if codeChallenge == "" && client.Public { // Force public clients to undergo PKCE.
		return fmt.Errorf("client '%s' is public and requires all users to submit a code challenge", client.ID)
	}

	if codeChallengeMethod == "" {
		codeChallengeMethod = CodeChallengePlain
	} else {
		if _, valid := CodeChallengeMethods[codeChallengeMethod]; !valid {
			return fmt.Errorf("unknown code challenge method '%s'", codeChallengeMethod)
		}
	}

	if codeChallenge != "" || codeChallengeMethod != CodeChallengePlain {
		switch codeChallengeMethod {
		case CodeChallengePlain:
			if !CodeVerifierRegex.MatchString(codeChallenge) {
				return errors.New("bad code challenge")
			}
		case CodeChallengeS256:
			hash, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(codeChallenge)
			if err != nil {
				return errors.New("code challenge is not base64 url-encoded with no padding")
			}
			if len(hash) != sha256.Size {
				return errors.New("code challenge is not a sha256 hash")
			}
		}
	}

	return nil
}
