// Package richauth holds the domain rules for OAuth 2.0 Rich Authorization Requests
// (RFC 9396): the authorization_details request parameter's one supported detail type,
// the limits on it, its parsing into canonical Detail values, and the canonical JSON
// snapshot carried on the authorization code and into the access token.
//
// Nothing here talks to a database or the browser. Whether a resource exists, whether a
// client is licensed for an action and whether a user currently holds it are questions the
// protocolvalidation and permissions packages answer with these Detail values as input.
// That split mirrors resource scopes: ResolveScope names a permission row, the validators
// and the checker decide who may have it.
package richauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/oauth"
)

// ParameterName is the RFC 9396 request parameter this package implements, under the one
// spelling the authorization endpoint reads it, the consent form names it nowhere, and the
// access token serializes its result: authorization_details.
const ParameterName = "authorization_details"

// ResourcePermissionDetailsType is the one authorization_details type this server
// implements, as discovery advertises it. An item of this type targets a resource by the
// service's existing resource identifier and asks for actions, each an existing permission
// identifier on that resource:
//
//	{"type":"urn:goiabada:resource-permission","resource":"backend-service","actions":["read"]}
//
// A URN in the server's own urn:goiabada namespace, like its ACR values, rather than a
// generic word that another authorization_details type registry could later collide with.
const ResourcePermissionDetailsType = "urn:goiabada:resource-permission"

// The limits an authorization_details request is accepted under. They bound the sealed
// ceremony value, the codes column and every error message that interpolates an identifier,
// so they are deliberately tighter than the columns that store them.
const (
	// MaxBytes bounds the raw parameter value in bytes, checked before it is parsed, so a
	// megabyte of malformed JSON costs no decoding. 8 KiB holds the item ceiling below.
	MaxBytes = 8192
	// MaxItems bounds how many detail items one request may carry.
	MaxItems = 20
	// MaxActionsPerItem bounds how many actions one item may name.
	MaxActionsPerItem = 50
	// maxIdentifierBytes bounds a resource or action identifier as sent. The database still
	// has to resolve it, so this is a shape bound and never an existence check.
	maxIdentifierBytes = 256
)

// Detail is one canonical authorization_details item: a type, a target resource and the
// actions requested on it. The ceremony stores canonical values, the authorization code
// stores their canonical JSON and the access token carries that JSON in its
// authorization_details claim, so the three representations are the same value.
type Detail struct {
	Type     string   `json:"type"`
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

// SupportedTypes is discovery's authorization_details_types_supported: the types Parse
// accepts, as a fresh slice a caller cannot reach the registry through.
func SupportedTypes() []string {
	return []string{ResourcePermissionDetailsType}
}

// requestError answers one malformed authorization_details request, all of them
// invalid_request: the parameter is a request parameter and every refusal below names what
// was wrong with its value rather than with the grant. The descriptions are deliberately
// distinct for the two readers RFC 9396 has, the integrator diagnosing a request and the
// test asserting each failure reaches the client as its own condition.
func requestError(format string, args ...any) *oauth.ErrorDetail {
	return oauth.NewErrorDetailWithHTTPStatus("invalid_request", fmt.Sprintf(format, args...), http.StatusBadRequest)
}

// Parse reads the authorization_details parameter exactly as the client sent it and
// answers the canonical detail set, or a refusal naming the first rule it broke. An empty
// parameter is no RAR request at all and answers (nil, nil): the scope-only path is
// unchanged.
//
// Canonical means: only the registered type is present, actions are sorted and unique,
// and items are sorted by resource with one item per resource. The ceremony never mutates a
// returned item's backing array: callers that narrow a set build a new one with Filter or
// Clone, which is what keeps the accepted request comparable to what was shown and
// approved.
func Parse(raw string) ([]Detail, *oauth.ErrorDetail) {
	if raw == "" {
		return nil, nil
	}

	if len(raw) > MaxBytes {
		return nil, requestError("The '%s' parameter is too long (%d bytes, the maximum is %d).",
			ParameterName, len(raw), MaxBytes)
	}

	// The top level has to be a JSON array. Decode into RawMessage first so an object, a
	// string or a number each get the "must be an array" answer rather than a decoder error,
	// and so null is refused as not-an-array rather than read as an empty request.
	trimmed := bytes.TrimSpace([]byte(raw))
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, requestError("The '%s' parameter must be a JSON array.", ParameterName)
	}

	var elements []json.RawMessage
	if err := json.Unmarshal(trimmed, &elements); err != nil {
		return nil, requestError("The '%s' parameter is not valid JSON: %v.", ParameterName, jsonError(err))
	}
	if len(elements) == 0 {
		return nil, requestError("The '%s' parameter must contain at least one authorization detail.", ParameterName)
	}
	if len(elements) > MaxItems {
		return nil, requestError("The '%s' parameter carries too many authorization details (%d, the maximum is %d).",
			ParameterName, len(elements), MaxItems)
	}

	details := make([]Detail, 0, len(elements))
	for i, element := range elements {
		where := fmt.Sprintf("%s[%d]", ParameterName, i)
		detail, err := parseItem(where, element)
		if err != nil {
			return nil, err
		}
		details = append(details, detail)
	}

	// One item per resource. Two items naming the same target are a duplicate the client
	// must fold together rather than something normalization silently merges: merging would
	// make the canonical set differ from the two rows the client sent, and a later edit that
	// made items carry item-level fields would have to guess whether they conflict.
	seenResources := make(map[string]int, len(details))
	for i, detail := range details {
		where := fmt.Sprintf("%s[%d]", ParameterName, i)
		if first, dup := seenResources[detail.Resource]; dup {
			return nil, requestError("%s duplicates resource %q, first named at %s[%d]: send one item per resource with every action in its actions array.",
				where, detail.Resource, ParameterName, first)
		}
		seenResources[detail.Resource] = i
	}

	sortDetails(details)
	return details, nil
}

// parseItem parses and validates one array element into a canonical Detail.
func parseItem(where string, raw json.RawMessage) (Detail, *oauth.ErrorDetail) {
	body := bytes.TrimSpace(raw)
	if len(body) == 0 || bytes.Equal(body, []byte("null")) || body[0] != '{' {
		return Detail{}, requestError("%s must be a JSON object.", where)
	}

	// Unknown fields are refused rather than dropped. The snapshot and the token can only
	// contain fields the consent screen displayed, and an item of this server's own type has
	// no defined extensions: accepting "locations" or another client-invented field and then
	// omitting it everywhere would misrepresent what was approved. The outer array decode
	// already guarantees no content follows the object inside this element.
	var detail Detail
	if err := unmarshalStrict(body, &detail); err != nil {
		return Detail{}, requestError("%s is not a valid authorization detail: %v.", where, jsonError(err))
	}

	if detail.Type == "" {
		return Detail{}, requestError("%s is missing its 'type' field.", where)
	}
	if detail.Type != ResourcePermissionDetailsType {
		return Detail{}, requestError("%s names an unsupported authorization details type %q. Supported types: %s.",
			where, detail.Type, ResourcePermissionDetailsType)
	}

	if err := validateIdentifier(where, "resource", detail.Resource); err != nil {
		return Detail{}, err
	}

	if detail.Actions == nil {
		return Detail{}, requestError("%s is missing its 'actions' field.", where)
	}
	if len(detail.Actions) == 0 {
		return Detail{}, requestError("%s must name at least one action.", where)
	}
	if len(detail.Actions) > MaxActionsPerItem {
		return Detail{}, requestError("%s names too many actions (%d, the maximum is %d).",
			where, len(detail.Actions), MaxActionsPerItem)
	}

	seenActions := make(map[string]bool, len(detail.Actions))
	for _, action := range detail.Actions {
		if err := validateIdentifier(where, "action", action); err != nil {
			return Detail{}, err
		}
		if seenActions[action] {
			return Detail{}, requestError("%s lists the action %q more than once.", where, action)
		}
		seenActions[action] = true
	}

	slices.Sort(detail.Actions)
	return detail, nil
}

// validateIdentifier enforces the cheap shape rules both resource and action identifiers
// share. Existence is deliberately not checked here: this runs before any database read,
// and an unknown identifier is a different refusal (invalid resource/action) from a
// malformed one.
func validateIdentifier(where, field, value string) *oauth.ErrorDetail {
	if value == "" {
		return requestError("%s is missing its '%s' field.", where, field)
	}
	if len(value) > maxIdentifierBytes {
		return requestError("%s has a %s longer than %d bytes.", where, field, maxIdentifierBytes)
	}
	if strings.TrimSpace(value) != value {
		return requestError("%s has a %s with leading or trailing whitespace: %q.", where, field, value)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return requestError("%s has a %s containing a control character.", where, field)
		}
	}
	return nil
}

// unmarshalStrict is json.Unmarshal with unknown fields refused, which the stdlib exposes
// only on Decoder.
func unmarshalStrict(body []byte, target *Detail) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// jsonError keeps the decoder's message but drops a trailing newline.
func jsonError(err error) string {
	return strings.TrimSpace(err.Error())
}

// sortDetails puts canonical items in resource order. There is one type, so the resource
// is the total ordering.
func sortDetails(details []Detail) {
	slices.SortFunc(details, func(a, b Detail) int {
		return strings.Compare(a.Resource, b.Resource)
	})
}

// CanonicalJSON is the immutable snapshot form: compact JSON of the canonical set, with
// "[]" for an empty one. The authorization code stores this and the access token claim
// parses it back, so bytes compared here are bytes the resource server receives.
func CanonicalJSON(details []Detail) string {
	if len(details) == 0 {
		return "[]"
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		// Unreachable for a value Parse or Filter built: Detail is three JSON-safe fields.
		// The empty form keeps a caller going rather than handing an empty string to a
		// NOT NULL column if that ever changes.
		return "[]"
	}
	return string(encoded)
}

// UnmarshalStored reads the snapshot stored on a code. An empty string and "[]" both mean
// a scope-only grant. A value that does not parse is an error the caller treats as
// fail-closed (invalid_grant), since every value this release writes passed CanonicalJSON.
func UnmarshalStored(stored string) ([]Detail, error) {
	if stored == "" || stored == "[]" {
		return nil, nil
	}
	var details []Detail
	if err := json.Unmarshal([]byte(stored), &details); err != nil {
		return nil, err
	}
	return details, nil
}

// Clone answers a deep copy sharing no array with the input, so a narrowed working copy
// can never write through the request it was filtered from.
func Clone(details []Detail) []Detail {
	if len(details) == 0 {
		return nil
	}
	cloned := make([]Detail, len(details))
	for i := range details {
		cloned[i] = Detail{
			Type:     details[i].Type,
			Resource: details[i].Resource,
			Actions:  slices.Clone(details[i].Actions),
		}
	}
	return cloned
}

// Equal reports whether two sets have the same canonical JSON. Both are expected to be
// canonical already; the comparison is therefore byte-wise.
func Equal(a, b []Detail) bool {
	return CanonicalJSON(a) == CanonicalJSON(b)
}

// Scope renders one action as the resource:permission scope string the rest of the
// permission system already speaks, so holdings can be re-checked with no second identifier
// grammar. Resource identifiers that cannot name a scope are resolved directly by the
// callers that need them.
func (d Detail) Scope(action string) string {
	return d.Resource + ":" + action
}
