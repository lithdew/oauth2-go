package oauth2_test

import (
	"fmt"
	"github.com/lithdew/oauth2-go"
	"github.com/stretchr/testify/require"
	"testing"
	"testing/quick"
)

func TestGenerateCodeChallengePKCE(t *testing.T) {
	f := func() bool {
		verifier, err := oauth2.GenerateCodeVerifierPKCE()
		require.NoError(t, err)

		fmt.Println(verifier)
		fmt.Println(oauth2.GenerateCodeChallengePKCE(verifier))

		return oauth2.CodeVerifierRegex.MatchString(verifier)
	}
	require.NoError(t, quick.Check(f, &quick.Config{}))
}
