package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// respondTokenExchange performs a validated RFC 8693 token exchange and answers with its one access
// token. The validated grant is mapped to the issuer's input here, the one place that crosses from
// what the request proved to what the issuer mints.
func (tr tokenResponder) respondTokenExchange(w http.ResponseWriter, r *http.Request,
	settings *record.Settings, grant *protocolvalidation.TokenExchangeGrant) {

	input := &issuance.TokenExchangeInput{
		Client:              grant.Client,
		SubjectUser:         grant.SubjectUser,
		SubjectTokenString:  grant.SubjectTokenString,
		SubjectJti:          grant.SubjectJti,
		SubjectTokenType:    grant.SubjectTokenType,
		SubjectIsRefresh:    grant.SubjectRefreshToken != nil,
		ActorTokenString:    grant.ActorTokenString,
		ActorJti:            grant.ActorJti,
		ActorSubject:        grant.ActorSubject,
		ActorClientId:       grant.ActorClientId,
		Scope:               grant.Scope,
		Audiences:           grant.Audiences,
		SessionIdentifier:   grant.SessionIdentifier,
		AuthStateGeneration: grant.AuthStateGeneration,
		AuthenticatedAt:     grant.AuthenticatedAt,
		AcrLevel:            grant.AcrLevel,
		AuthMethods:         grant.AuthMethods,
		Act:                 grant.Act,
		RequestedScope:      grant.RequestedScope,
		RequestedAudience:   grant.RequestedAudience,
		RequestedResource:   grant.RequestedResource,
		RequestedTokenType:  grant.RequestedTokenType,
	}

	tokenResponse, err := tr.issuer.IssueTokenExchangeGrant(r.Context(), settings, input)
	if err != nil {
		tr.refuse(w, r, oidc.GrantTypeTokenExchange, err)
		return
	}

	tr.auditLogger.Log(r.Context(), audit.EventTokenIssuedTokenExchangeResponse, map[string]interface{}{
		"client_id":       grant.Client.Id,
		"subject_user_id": grant.SubjectUser.Id,
		"scope":           grant.Scope,
		"audience":        grant.Audiences,
		// Who acted, when an actor token was presented; the act chain itself is in the token and
		// recorded on the token_exchanges row.
		"actor_client_id": grant.ActorClientId,
	})

	tr.writeTokenResponse(w, r, oidc.GrantTypeTokenExchange, tokenResponse)
}
