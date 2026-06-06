package csrf_test

import (
	"testing"

	"github.com/mikaelstaldal/go-server-common/csrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveServerOrigin_DefaultFromAddrPort(t *testing.T) {
	origin, err := csrf.ResolveServerOrigin("", "127.0.0.1", 8080)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080", origin)
}

func TestResolveServerOrigin_FromPublicURL(t *testing.T) {
	origin, err := csrf.ResolveServerOrigin("https://example.com", "127.0.0.1", 8080)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", origin)
}

func TestResolveServerOrigin_FromPublicURLDropsPath(t *testing.T) {
	origin, err := csrf.ResolveServerOrigin("https://example.com:9000/ignored", "127.0.0.1", 8080)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com:9000", origin)
}

func TestResolveServerOrigin_InvalidPublicURL(t *testing.T) {
	_, err := csrf.ResolveServerOrigin("not-a-url", "127.0.0.1", 8080)
	assert.Error(t, err)
}
