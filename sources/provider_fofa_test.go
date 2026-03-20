package sources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProviderGetKeysSupportsKeyOnlyFOFA(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		rawCredential string
		expectedEmail string
		expectedKey   string
	}{
		{
			name:          "key only",
			rawCredential: "test-key",
			expectedKey:   "test-key",
		},
		{
			name:          "legacy email and key",
			rawCredential: "user@example.com:test-key",
			expectedEmail: "user@example.com",
			expectedKey:   "test-key",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := &Provider{Fofa: []string{tc.rawCredential}}
			keys := provider.GetKeys()

			require.Equal(t, tc.expectedEmail, keys.FofaEmail)
			require.Equal(t, tc.expectedKey, keys.FofaKey)
		})
	}
}

func TestProviderLoadProviderKeysFromEnvLoadsFOFAKeyOnly(t *testing.T) {
	t.Setenv("FOFA_KEY", "env-key")

	provider := &Provider{}
	provider.LoadProviderKeysFromEnv()

	require.Equal(t, []string{"env-key"}, provider.Fofa)
}
