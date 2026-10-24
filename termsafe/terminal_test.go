package termsafe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalControlsAndInvalidUTF8(t *testing.T) {
	var input, expected strings.Builder
	for r := rune(0); r <= 0x9f; r++ {
		input.WriteRune(r)
		switch {
		case r == '\t' || r == '\n' || r >= 0x20 && r < 0x7f:
			expected.WriteRune(r)
		default:
			// JSON provides exactly the Unicode escape spelling used for controls.
			// C1 and DEL must be escaped explicitly.
			const hex = "0123456789abcdef"
			expected.WriteString("\\u00")
			expected.WriteByte(hex[r>>4])
			expected.WriteByte(hex[r&15])
		}
	}
	input.WriteString("\xff\x9b\xc2\x1b\r\n\r")
	expected.WriteString("\\xff\\x9b\\xc2\\u001b\r\n\\u000d")
	var output bytes.Buffer
	require.NoError(t, Copy(&output, strings.NewReader(input.String())))
	assert.Equal(t, expected.String(), output.String())
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestTerminalWriteError(t *testing.T) {
	require.ErrorContains(t, Copy(failedWriter{}, strings.NewReader("hello")), "write failed")
}

func TestTerminalReadErrorFlushesOutput(t *testing.T) {
	readErr := errors.New("download interrupted")
	reader := io.MultiReader(strings.NewReader("hello\x1b"), iotest.ErrReader(readErr))
	var output bytes.Buffer
	require.ErrorIs(t, Copy(&output, reader), readErr)
	assert.Equal(t, "hello\\u001b", output.String())
	require.ErrorContains(t, Copy(failedWriter{}, io.MultiReader(strings.NewReader("hello"), iotest.ErrReader(readErr))), "write failed")
}

func TestUnicodeAndIdempotence(t *testing.T) {
	input := "café 日本語 �\t\n\r\n\r\x1b\a\x9b\xff\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
	expected := "café 日本語 �\t\n\r\n" + `\u000d\u001b\u0007\x9b\xff\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069`
	assert.Equal(t, expected, String(input))
	assert.Equal(t, expected, String(expected))
	var output bytes.Buffer
	require.NoError(t, Copy(&output, iotest.OneByteReader(strings.NewReader(input))))
	assert.Equal(t, expected, output.String())
}

func TestJSONValuesPreserved(t *testing.T) {
	value := "hello\x1b\a\r\u009b\u202e"
	input, err := json.Marshal(map[string]string{"text": value})
	require.NoError(t, err)
	safe := String(string(input))
	assert.NotContains(t, safe, "\u009b")
	assert.NotContains(t, safe, "\u202e")
	var decoded map[string]string
	require.NoError(t, json.Unmarshal([]byte(safe), &decoded))
	assert.Equal(t, value, decoded["text"])
}
