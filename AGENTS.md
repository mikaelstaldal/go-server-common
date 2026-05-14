### Testing Guidelines

For all Go tests, use the `testify` library for assertions.

- Use `github.com/stretchr/testify/assert` for non-fatal assertions (equivalent to `t.Errorf`).
- Use `github.com/stretchr/testify/require` for fatal assertions that should stop the test execution immediately (equivalent to `t.Fatalf`).

Example:
```go
import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestSomething(t *testing.T) {
    val, err := DoSomething()
    require.NoError(t, err)
    assert.Equal(t, "expected", val)
}
```
