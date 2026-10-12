package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// CreateTokenExchange writes one completed exchange in the caller's transaction. It is the commit
// point of an exchange: the row exists if and only if its access token was minted, so an
// idempotent retry that finds the request_hash unique key already taken returns the stored token
// rather than minting a second lineage. A lost race arrives back as data.ErrUniqueViolation and
// the caller reruns its transaction once, as RecordRefreshTokenFamilyRevoked does.
func (d *Database) CreateTokenExchange(ctx context.Context, tx *sql.Tx, exchange *record.TokenExchange) error {

	now := time.Now().UTC()
	if !exchange.CreatedAt.Valid {
		exchange.CreatedAt = sql.NullTime{Time: now, Valid: true}
	}
	exchange.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	insertBuilder := sqlbuilder.NewStruct(new(record.TokenExchange)).
		For(d.Flavor).
		InsertInto("token_exchanges", exchange)

	query, args := insertBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return errs.Wrap(err, "unable to create token exchange")
	}
	return nil
}

// GetTokenExchangeByRequestHash looks an exchange up by its canonical request hash, the
// idempotency handle. It answers (nil, nil) for a hash no exchange recorded.
func (d *Database) GetTokenExchangeByRequestHash(ctx context.Context, tx *sql.Tx, requestHash string) (*record.TokenExchange, error) {
	if requestHash == "" {
		return nil, errs.New("can't look up a token exchange with an empty request hash")
	}
	return d.getTokenExchange(ctx, tx, "request_hash", requestHash)
}

// GetTokenExchangeByIssuedJti looks an exchange up by the jti of the token it issued. It is the
// handle the bearer session guard walks to invalidate a derived token whose client or source
// grant changed. It answers (nil, nil) for a jti no exchange recorded: a token claiming an act
// lineage with no row fails closed at its caller.
func (d *Database) GetTokenExchangeByIssuedJti(ctx context.Context, tx *sql.Tx, exchangeJti string) (*record.TokenExchange, error) {
	if exchangeJti == "" {
		return nil, errs.New("can't look up a token exchange with an empty exchange jti")
	}
	return d.getTokenExchange(ctx, tx, "exchange_jti", exchangeJti)
}

func (d *Database) getTokenExchange(ctx context.Context, tx *sql.Tx, column, value string) (*record.TokenExchange, error) {

	tokenExchangeStruct := sqlbuilder.NewStruct(new(record.TokenExchange)).
		For(d.Flavor)

	selectBuilder := tokenExchangeStruct.SelectFrom("token_exchanges")
	selectBuilder.Where(selectBuilder.Equal(column, value))

	query, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		var exchange record.TokenExchange
		addr := tokenExchangeStruct.Addr(&exchange)
		if err := rows.Scan(addr...); err != nil {
			return nil, errs.Wrap(err, "unable to scan token exchange")
		}
		if err := rows.Err(); err != nil {
			return nil, errs.Wrap(err, "unable to read query results")
		}
		return &exchange, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}
	return nil, nil
}
