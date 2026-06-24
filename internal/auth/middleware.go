// Copyright 2026 Koopa. All rights reserved.

// middleware.go holds the JWT access-token validator that gates every
// admin route. Ordering note (enforced by cmd/app/routes.go): this
// middleware composes OUTSIDE api.ActorMiddleware so JWT validation
// short-circuits unauthenticated requests before a DB tx is opened.
// A request that fails auth never opens a pool connection.

package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Koopa0/koopa/internal/api"
)

// Middleware returns an HTTP middleware that validates JWT access tokens.
func Middleware(secret string) func(http.Handler) http.Handler {
	secretBytes := []byte(secret)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing authorization header")
				return
			}

			token, found := strings.CutPrefix(header, "Bearer ")
			if !found {
				api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid authorization format")
				return
			}

			claims := &Claims{}
			parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return secretBytes, nil
			})
			if err != nil || !parsed.Valid {
				api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
				return
			}

			// The token is validated but not stored: no production path reads
			// JWT claims (the admin actor is a literal passed to ActorMiddleware,
			// not resolved from claims). Re-introduce a claims reader here if and
			// when multi-admin lands.
			next.ServeHTTP(w, r)
		})
	}
}
