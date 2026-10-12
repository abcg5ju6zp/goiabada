package deviceflow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceCode_IsHighEntropy(t *testing.T) {
	code := NewDeviceCode()
	assert.Len(t, code, deviceCodeLength)
	assert.NotEqual(t, code, NewDeviceCode(), "each device code is fresh randomness")
}

func TestNewUserCode_IsTypeableAndGrouped(t *testing.T) {
	code := NewUserCode()
	require.Len(t, code, userCodeLength+1, "XXXX-XXXX with one dash")
	assert.Equal(t, 1, strings.Count(code, "-"), "exactly one grouping dash")
	parts := strings.Split(code, "-")
	require.Len(t, parts, 2)
	assert.Len(t, parts[0], userCodeLength/2)
	assert.Len(t, parts[1], userCodeLength/2)
	for _, r := range strings.ReplaceAll(code, "-", "") {
		assert.Contains(t, string(UserCodeAlphabet), string(r), "only the unambiguous alphabet")
	}
}

func TestNormalizeUserCode(t *testing.T) {
	raw := NewUserCode()

	for name, in := range map[string]string{
		"upper with dash":   strings.ToUpper(raw),
		"lower with spaces": "  " + strings.ToLower(raw) + " ",
		"lower no dash":     strings.ToLower(strings.ReplaceAll(raw, "-", "")),
		"upper no dash":     strings.ReplaceAll(strings.ToUpper(raw), "-", ""),
		"tabs":              "\t" + strings.ToUpper(raw) + "\t",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, strings.ToUpper(strings.ReplaceAll(raw, "-", "")), NormalizeUserCode(in))
		})
	}
	assert.Equal(t, "", NormalizeUserCode("   "))
}

func TestConstants_PinTheProtocolTiming(t *testing.T) {
	assert.Equal(t, 5, IntervalSeconds)
	assert.Equal(t, 10, SlowDownIncrementSeconds)
	assert.Equal(t, 1800, LifetimeSeconds)
}
