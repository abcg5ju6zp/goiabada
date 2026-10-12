package richauth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_EmptyIsNoRequest(t *testing.T) {
	details, err := Parse("")
	require.Nil(t, err)
	assert.Nil(t, details)
}

func TestParse_Canonicalizes(t *testing.T) {
	raw := `[
		{"type":"urn:goiabada:resource-permission","resource":"b-service","actions":["write","read"]},
		{"type":"urn:goiabada:resource-permission","resource":"a-service","actions":["admin"]}
	]`
	details, err := Parse(raw)
	require.Nil(t, err)
	require.Len(t, details, 2)

	// Items sorted by resource, actions sorted and unique.
	assert.Equal(t, []Detail{
		{Type: ResourcePermissionDetailsType, Resource: "a-service", Actions: []string{"admin"}},
		{Type: ResourcePermissionDetailsType, Resource: "b-service", Actions: []string{"read", "write"}},
	}, details)
}

func TestParse_ErrorsAreDeterministic(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"not json", `{`},
		{"top level is an object", `{}`},
		{"top level is null", `null`},
		{"top level is a string", `"[]"`},
		{"empty array", `[]`},
		{"element is not an object", `[42]`},
		{"element is null", `[null]`},
		{"unknown field", `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":["a"],"locations":["x"]}]`},
		{"missing type", `[{"resource":"r","actions":["a"]}]`},
		{"unsupported type", `[{"type":"urn:example:other","resource":"r","actions":["a"]}]`},
		{"missing resource", `[{"type":"urn:goiabada:resource-permission","actions":["a"]}]`},
		{"empty resource", `[{"type":"urn:goiabada:resource-permission","resource":"","actions":["a"]}]`},
		{"padded resource", `[{"type":"urn:goiabada:resource-permission","resource":" r ","actions":["a"]}]`},
		{"missing actions", `[{"type":"urn:goiabada:resource-permission","resource":"r"}]`},
		{"null actions", `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":null}]`},
		{"empty actions", `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":[]}]`},
		{"empty action", `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":[""]}]`},
		{"padded action", `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":[" a"]}]`},
		{"duplicate action", `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":["a","a"]}]`},
		{"duplicate resource", `[
			{"type":"urn:goiabada:resource-permission","resource":"r","actions":["a"]},
			{"type":"urn:goiabada:resource-permission","resource":"r","actions":["b"]}]`},
		{"wrong action kind", `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":[1]}]`},
		{"wrong resource kind", `[{"type":"urn:goiabada:resource-permission","resource":7,"actions":["a"]}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details, err := Parse(tt.raw)
			require.NotNil(t, err, "Parse must refuse %q", tt.name)
			assert.Nil(t, details)
			assert.Equal(t, "invalid_request", err.Code())
			assert.Equal(t, 400, err.HTTPStatus())
		})
	}
}

func TestParse_Limits(t *testing.T) {
	t.Run("raw byte bound", func(t *testing.T) {
		raw := `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":["a"],"pad":"` + strings.Repeat("x", MaxBytes) + `"]`
		// pad is an unknown field too, but the size check must come first either way.
		_, err := Parse(raw)
		require.NotNil(t, err)
		assert.Contains(t, err.Description(), "too long")
	})

	t.Run("item bound", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString("[")
		for i := 0; i <= MaxItems; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"type":"urn:goiabada:resource-permission","resource":"r` + itoa(i) +
				`","actions":["a"]}`)
		}
		sb.WriteString("]")
		_, err := Parse(sb.String())
		require.NotNil(t, err)
		assert.Contains(t, err.Description(), "too many authorization details")
	})

	t.Run("action bound", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString(`[{"type":"urn:goiabada:resource-permission","resource":"r","actions":[`)
		for i := 0; i <= MaxActionsPerItem; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`"a` + itoa(i) + `"`)
		}
		sb.WriteString("]}]")
		_, err := Parse(sb.String())
		require.NotNil(t, err)
		assert.Contains(t, err.Description(), "too many actions")
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestCanonicalJSONAndStoredRoundTrip(t *testing.T) {
	details, err := Parse(`[{"type":"urn:goiabada:resource-permission","resource":"r","actions":["b","a"]}]`)
	require.Nil(t, err)

	stored := CanonicalJSON(details)
	assert.Equal(t, `[{"type":"urn:goiabada:resource-permission","resource":"r","actions":["a","b"]}]`, stored)

	back, storedErr := UnmarshalStored(stored)
	require.NoError(t, storedErr)
	assert.True(t, Equal(details, back))
}

func TestCanonicalJSON_Empty(t *testing.T) {
	assert.Equal(t, "[]", CanonicalJSON(nil))
	back, storedErr := UnmarshalStored("[]")
	require.NoError(t, storedErr)
	assert.Nil(t, back)
	back, storedErr = UnmarshalStored("")
	require.NoError(t, storedErr)
	assert.Nil(t, back)
}

func TestUnmarshalStored_MalformedFails(t *testing.T) {
	_, err := UnmarshalStored(`{broken`)
	require.Error(t, err)
}

func TestClone_DoesNotShareArrays(t *testing.T) {
	original, err := Parse(`[{"type":"urn:goiabada:resource-permission","resource":"r","actions":["a","b"]}]`)
	require.Nil(t, err)
	cloned := Clone(original)
	cloned[0].Actions[0] = "changed"
	assert.Equal(t, "a", original[0].Actions[0])
}

func TestScope(t *testing.T) {
	d := Detail{Resource: "billing", Actions: []string{"read"}}
	assert.Equal(t, "billing:read", d.Scope("read"))
}

// guard against accidental drift of the published type.
func TestSupportedTypes(t *testing.T) {
	assert.Equal(t, []string{"urn:goiabada:resource-permission"}, SupportedTypes())
	got := SupportedTypes()
	got[0] = "mutated"
	assert.Equal(t, ResourcePermissionDetailsType, SupportedTypes()[0])
}
