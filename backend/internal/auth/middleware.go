package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/koopa0/blog-backend/internal/api"
)

type contextKey struct{}

var claimsKey = contextKey{}

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

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext retrieves JWT claims from the request context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*Claims)
	return claims, ok
}
