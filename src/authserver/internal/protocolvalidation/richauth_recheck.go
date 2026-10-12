package protocolvalidation

import (
	"context"
	"net/http"
	"slices"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/richauth"
	"github.com/leodip/goiabada/core/oauth"
)

// recheckAuthorizationDetails is the token endpoint's fail-closed re-validation of the
// immutable authorization_details snapshot on an authorization code, run when the code is
// redeemed and again whenever a refresh token descended from it is presented. It answers
// the same four questions /auth/authorize did, against current data:
//
//  1. the snapshot still parses and uses a registered type — a value this server never
//     wrote is refused as an invalid grant;
//  2. every resource still exists and declares every action;
//  3. the client presenting the grant is still licensed for every permission (row id,
//     never the bare identifier);
//  4. the user the code names still HOLDS every permission, directly or through a
//     current group membership.
//
// It never narrows. The consent page approved exactly this set, and the access token's
// claim is required to equal the code's snapshot, so one action withdrawn or unlicensed
// refuses the whole grant with invalid_grant; a refreshed token must not quietly carry
// fewer actions than the approved set either. The claim is then safe to copy from the
// code verbatim.
//
// All of it sits below client authentication and PKCE at the call site, like every other
// grant-state check, so an unauthenticated presenter learns nothing from the answer.
func (val *TokenValidator) recheckAuthorizationDetails(ctx context.Context, client *record.Client, code *record.Code) error {
	details, err := richauth.UnmarshalStored(code.AuthorizationDetails)
	if err != nil {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.", http.StatusBadRequest)
	}
	if len(details) == 0 {
		return nil
	}

	if err := val.database.ClientLoadPermissions(ctx, nil, client); err != nil {
		return err
	}

	for _, detail := range details {
		if detail.Type != richauth.ResourcePermissionDetailsType {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"The authorization code carries an unsupported authorization_details type.", http.StatusBadRequest)
		}

		resource, err := val.database.GetResourceByResourceIdentifier(ctx, nil, detail.Resource)
		if err != nil {
			return err
		}
		if resource == nil {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"The resource the authorization code granted access to no longer exists.", http.StatusBadRequest)
		}

		declared, err := val.database.GetPermissionsByResourceId(ctx, nil, resource.Id)
		if err != nil {
			return err
		}

		for _, action := range detail.Actions {
			var permission *record.Permission
			for i := range declared {
				if declared[i].PermissionIdentifier == action {
					permission = &declared[i]
					break
				}
			}
			if permission == nil {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
					"The resource no longer declares one of the granted actions.", http.StatusBadRequest)
			}

			if !slices.ContainsFunc(client.Permissions, func(p record.Permission) bool { return p.Id == permission.Id }) {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
					"The client is no longer licensed for one of the granted permissions.", http.StatusBadRequest)
			}

			held, err := val.permissionChecker.UserHasScopePermission(ctx, code.UserId, detail.Scope(action))
			if err != nil {
				return err
			}
			if !held {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
					"The user no longer holds one of the permissions the consent approved.", http.StatusBadRequest)
			}
		}
	}

	return nil
}
