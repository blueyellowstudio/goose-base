# Authentication, Authorization & Identity Manager

These three packages work together to handle the full lifecycle of user identity in a service: who a user is (`identityManager`), whether they are allowed in (`authorization`), and what actions they can perform after logging in (`authentication`).

---

## identityManager

**What it does**

`identityManager` is the lowest layer. It talks directly to the identity provider (Supabase Auth) and owns all operations that touch user records. It knows nothing about HTTP cookies, JWT claims, or request context — it only deals with users as data.

The `IdentityManager` interface covers:
- **Register** — sign up a new user with email + password
- **Authenticate** — exchange credentials for access + refresh tokens
- **RefreshToken** — get a new access token from a refresh token
- **VerifyEmailOtp / VerifyTokenHash** — confirm email addresses or auth links (invite, magic link, recovery, signup)
- **SendMagicLink / SendPasswordResetEmail / ResendVerificationEmail** — trigger email flows
- **SendInvite** — invite a user by email (admin-initiated)
- **CreateManagedUser** — create a user on behalf of an admin, skipping email confirmation
- **GetUserEmail** — look up a user's email by UUID
- **UpdateUserPassword** — set a new password for a given user UUID
- **DisableUser** — ban the user for ~100 years
- **DeleteUser** — permanently remove the user from the identity provider

The `SupabaseIdentityManager` implementation uses two key types:
- **Anon key** for public-facing operations (login, register, token refresh, OTP verification, password reset)
- **Service role key** for privileged admin operations (create, invite, disable, delete, get email)

---

## authorization

**What it does**

`authorization` sits at the HTTP boundary. Its job is to validate an incoming JWT and populate the request context with user identity so that downstream handlers don't need to touch tokens at all.

**How it works**

1. The `Handler` middleware runs on every protected route.
2. It extracts a token from the `Authorization: Bearer` header or a named cookie.
3. It validates the JWT signature (HS256) with the configured secret.
4. It delegates further claim validation and context population to the `TokenHandler`.
5. In non-production environments, if the `AuthorizationOverwrite` header is present with a UUID, it bypasses token validation entirely — useful for local development.

**`TokenHandler` interface**

The `TokenHandler` is the seam between generic JWT validation and your application's domain. You implement it once per service and inject it. It has four methods:

| Method | Responsibility |
|---|---|
| `CreateContext` | Reads validated JWT claims, extracts domain fields, stores them in context |
| `CreateDebugContext` | Creates a context entry from a raw UUID without any token — dev/test only |
| `ValidateToken` | Checks audience, expiry, and required claims |
| `GetIdentityFromContext` | Reads the stored context entry and returns a `ContextIdentity` |

`ContextIdentity` is the transport-safe struct (just `UserID uuid.UUID` and `UserEmail string`) used by any code that needs to know who the caller is.

---

## authentication

**What it does**

`authentication` builds HTTP handlers on top of the two layers above. It handles the session lifecycle from the user's perspective: cookies in, cookies out.

It holds a reference to both an `IdentityManager` (for actual auth operations) and a `TokenHandler` (for reading identity from context in protected handlers).

**HTTP handlers**

| Handler | Route intent |
|---|---|
| `LoginHandler` | POST — authenticate with email + password, set auth cookies |
| `RefreshAuthHandler` | POST — refresh access token from body or cookie, update cookies |
| `LogoutHandler` | any — clear auth cookies |
| `AuthLinkHandler` | GET — handle email link callbacks (invite, magic link, recovery, signup), set auth cookies and redirect |
| `RequestPasswordResetHandler` | POST — send a password reset email (always responds 200 to avoid enumeration) |
| `ResetPasswordHandler` | POST — set a new password using identity from context (called after recovery link) |
| `ChangePasswordHandler` | POST — verify current password then set a new one |
| `DisableAccountHandler` | POST — disable the calling user's account and clear cookies |
| `DeleteAccountHandler` | POST — delete the calling user's account and clear cookies |

Cookies are set as `HttpOnly`, `Secure` in production (`SameSite=Strict`), and `SameSite=Lax` in development. Both the access token cookie and the refresh token cookie are managed together with a 7-day max age.

---

## Practical Example

### Setup

```go
// your service's authorization package — implements TokenHandler for your domain
tokenHandler := authorization.NewTokenHandler()

identityManager := identityManager.NewSupabaseIdentityManager(
    "https://xyzproject.supabase.co",
    "eyJ...service-role-key...",
    "eyJ...anon-key...",
)

authz := authorization.NewAuthorization(
    "auth_token",         // tokenCookieName — name of the access token cookie
    []byte("my-jwt-secret"),
    tokenHandler,
    true,                 // isProduction
)

authn := authentication.NewAuthentication(
    identityManager,
    tokenHandler,
    "https://myapp.com",  // appUrl — used for redirect targets in link flows
    "auth_token",         // tokenCookieName
    "refresh_token",      // refreshTokenCookieName
    true,                 // isProduction
)
```

### Wiring routes

```go
mux := http.NewServeMux()

// Public auth routes
mux.HandleFunc("/auth/login", authn.LoginHandler)
mux.HandleFunc("/auth/refresh", authn.RefreshAuthHandler)
mux.HandleFunc("/auth/logout", authn.LogoutHandler)
mux.HandleFunc("/auth/link", authn.AuthLinkHandler)
mux.HandleFunc("/auth/password/request-reset", authn.RequestPasswordResetHandler)

// Protected routes — every request passes through the authorization middleware
protected := http.NewServeMux()
protected.HandleFunc("/auth/password/reset", authn.ResetPasswordHandler)
protected.HandleFunc("/auth/password/change", authn.ChangePasswordHandler)
protected.HandleFunc("/auth/account/disable", authn.DisableAccountHandler)
protected.HandleFunc("/auth/account/delete", authn.DeleteAccountHandler)
protected.HandleFunc("/api/orders", ordersHandler)

mux.Handle("/", authz.Handler(protected))
```

### Implementing TokenHandler

This is the only piece you write yourself per service. It translates raw JWT claims into your domain's user struct and stores it in context. The example below is a Supabase-flavoured implementation.

```go
package authorization

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/blueyellowstudio/goose-base/authorization"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

// NewTokenHandler creates a TokenHandler implementation for translating JWT claims into request context claims.
func NewTokenHandler() authorization.TokenHandler {
    return &supabaseTokenHandler{}
}

type supabaseTokenHandler struct{}

// CreateContext validates token claims and stores derived user claims in the request context.
func (h *supabaseTokenHandler) CreateContext(ctx context.Context, claims jwt.MapClaims) (context.Context, error) {
    if err := h.ValidateToken(claims); err != nil {
        return nil, err
    }

    userIDString, ok := claims["sub"].(string)
    if !ok {
        return nil, errors.New("missing sub")
    }

    userID, err := uuid.Parse(userIDString)
    if err != nil {
        return nil, fmt.Errorf("invalid user id: %w", err)
    }

    userClaims := &UserClaims{
        UserID:   userID,
        Username: extractUserName(claims),
        Email:    extractStringClaim(claims, "email"),
    }

    return WithUser(ctx, userClaims), nil
}

// CreateDebugContext creates request context claims without a token for local or debug usage.
func (h *supabaseTokenHandler) CreateDebugContext(ctx context.Context, userID uuid.UUID) (context.Context, error) {
    userClaims := &UserClaims{
        UserID: userID,
        Email:  "debug@local",
    }
    return WithUser(ctx, userClaims), nil
}

// ValidateToken ensures required claims are present and the token is still valid.
func (h *supabaseTokenHandler) ValidateToken(claims jwt.MapClaims) error {
    if !hasAuthenticatedAudience(claims["aud"]) {
        return errors.New("invalid audience")
    }

    expirationTime, err := claims.GetExpirationTime()
    if err != nil || expirationTime == nil || expirationTime.Before(time.Now()) {
        return errors.New("token expired")
    }

    if _, ok := claims["sub"].(string); !ok {
        return errors.New("missing sub")
    }

    return nil
}

// GetIdentityFromContext maps stored context claims into a transport-safe context identity object.
func (h *supabaseTokenHandler) GetIdentityFromContext(ctx context.Context) (authorization.ContextIdentity, error) {
    claims := GetUserClaims(ctx)
    if claims == nil {
        return authorization.ContextIdentity{}, errors.New("missing user claims in context")
    }

    if claims.UserID == uuid.Nil {
        return authorization.ContextIdentity{}, errors.New("missing user id in context")
    }

    return authorization.ContextIdentity{
        UserID:    claims.UserID,
        UserEmail: claims.Email,
    }, nil
}

func extractUserName(claims jwt.MapClaims) string {
    userMetadata, ok := claims["user_metadata"].(map[string]interface{})
    if !ok {
        return ""
    }
    userName, ok := userMetadata["username"].(string)
    if !ok {
        return ""
    }
    return userName
}

func extractStringClaim(claims jwt.MapClaims, claimKey string) string {
    claimValue, ok := claims[claimKey].(string)
    if !ok {
        return ""
    }
    return claimValue
}

func hasAuthenticatedAudience(audienceClaim interface{}) bool {
    switch audienceValue := audienceClaim.(type) {
    case string:
        return audienceValue == "authenticated"
    case []interface{}:
        for _, audience := range audienceValue {
            audienceString, ok := audience.(string)
            if ok && audienceString == "authenticated" {
                return true
            }
        }
    }
    return false
}
```

### Reading identity in a handler

Once the authorization middleware has run, any downstream handler can read the caller's identity from context without touching the JWT:

```go
func ordersHandler(w http.ResponseWriter, r *http.Request) {
    identity, err := tokenHandler.GetIdentityFromContext(r.Context())
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // identity.UserID and identity.UserEmail are now available
    orders, err := store.GetOrdersForUser(r.Context(), identity.UserID)
    // ...
}
```

### Request flow

```
Client request
    │
    ▼
authz.Handler (middleware)
    ├── non-production + AuthorizationOverwrite header → CreateDebugContext → context populated
    ├── Bearer header or cookie → validateToken (HS256 + TokenHandler.ValidateToken)
    │       └── TokenHandler.CreateContext → context populated
    └── no token / invalid → 401 Unauthorized
    │
    ▼
Your handler
    └── tokenHandler.GetIdentityFromContext(ctx) → ContextIdentity{UserID, UserEmail}
```
