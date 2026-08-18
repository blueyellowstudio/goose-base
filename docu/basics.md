# Authentication, Authorization & Identity Manager

These three packages work together to handle the full lifecycle of user identity in a service: who a user is (`identityManager`), whether they are allowed in (`authorization`), and what actions they can perform after logging in (`authentication`).

The design goal of the `authentication` package is that **a browser client never holds a token in JavaScript**. Every handler that produces a session writes it into `HttpOnly` cookies instead of returning tokens in a response body. Native clients that can keep a token safely are unaffected — `authorization` still reads the `Authorization` header, and prefers it over the cookie.

---

## identityManager

**What it does**

`identityManager` is the lowest layer. It talks directly to the identity provider (Supabase Auth) and owns all operations that touch user records. It knows nothing about HTTP cookies, JWT claims, or request context — it only deals with users as data.

The `IdentityManager` interface covers:
- **Register** — sign up a new user with email + password
- **Authenticate** — exchange credentials for access + refresh tokens
- **RefreshToken** — get a new access token from a refresh token
- **ExchangeOAuthCode** — complete a PKCE authorization: trade an authorization code plus its verifier for a session (see [OAuth](#oauth-pkce-flow))
- **VerifyEmailOtp / VerifyTokenHash** — confirm email addresses or auth links (invite, magic link, recovery, signup)
- **SendMagicLink / SendPasswordResetEmail / ResendVerificationEmail** — trigger email flows
- **SendInvite** — invite a user by email (admin-initiated)
- **CreateManagedUser** — create a user on behalf of an admin, skipping email confirmation
- **GetUserEmail** — look up a user's email by UUID
- **UpdateUserPassword** — set a new password for a given user UUID
- **DisableUser** — ban the user for ~100 years
- **DeleteUser** — permanently remove the user from the identity provider

The `SupabaseIdentityManager` implementation uses two key types:
- **Anon key** for public-facing operations (login, register, token refresh, OTP verification, password reset, OAuth code exchange)
- **Service role key** for privileged admin operations (create, invite, disable, delete, get email)

### OTP types

`VerifyEmailOtp` takes an `EmailOtpType`. Picking the wrong one fails at runtime with an opaque "invalid or expired OTP", so the distinction matters:

| Constant | Value | Verifies |
|---|---|---|
| `EmailOtpTypeSignup` | `signup` | the code from a registration confirmation email |
| `EmailOtpTypeRecovery` | `recovery` | a password-recovery link |
| `EmailOtpTypeMagicLink` | `magiclink` | a magic **link**'s `token_hash` |
| `EmailOtpTypeEmail` | `email` | the numeric **code** from a passwordless sign-in |
| `EmailOtpTypeInvite` | `invite` | an invitation link |
| `EmailOtpTypeEmailChange` | `email_change` | an email-change confirmation |

`EmailOtpTypeMagicLink` and `EmailOtpTypeEmail` both belong to the passwordless flow but are **not** interchangeable: the link carries a `token_hash`, the email body's `{{ .Token }}` carries a numeric code.

> **`SendMagicLink` does not create users.** It posts to `/auth/v1/otp` with `create_user=false`, not the deprecated `/auth/v1/magiclink`, which creates a user for any address handed to it. That endpoint is normally reached from a public login form, where auto-creation turns the form into an unauthenticated account-creation and email-enumeration surface.

---

## authorization

**What it does**

`authorization` sits at the HTTP boundary. Its job is to validate an incoming JWT and populate the request context with user identity so that downstream handlers don't need to touch tokens at all.

**How it works**

1. The `Handler` middleware runs on every protected route.
2. It extracts a token from the `Authorization: Bearer` header **or**, failing that, a named cookie. The header is checked first, so a native client sending a header and a browser sending a cookie can be served by the same routes.
3. It validates the JWT signature — see [signing algorithms](#signing-algorithms) below.
4. It delegates further claim validation and context population to the `TokenHandler`.
5. In non-production environments, if the `AuthorizationOverwrite` header is present with a UUID, it bypasses token validation entirely — useful for local development.

### Signing algorithms

Which algorithms are accepted follows from what you configure, and nothing else:

| Configuration | Accepted |
|---|---|
| `NewAuthorization` (secret only) | `HS256` |
| `NewAuthorizationWithJWKS` (secret + JWKS URL) | `HS256` and `ES256` |
| `NewAuthorizationWithJWKS` with an **empty** secret | `ES256` only |

That last row is how you retire a symmetric secret: keep both during the migration, then drop the secret from the environment. **An empty secret and an empty JWKS URL accepts nothing** and every request fails authorization with no useful explanation — guard against it at startup.

### `TokenHandler` interface

The `TokenHandler` is the seam between generic JWT validation and your application's domain. You implement it once per service and inject it. It has four methods:

| Method | Responsibility |
|---|---|
| `CreateContext` | Reads validated JWT claims, extracts domain fields, stores them in context |
| `CreateDebugContext` | Creates a context entry from a raw UUID without any token — dev/test only |
| `ValidateToken` | Checks audience, expiry, and required claims |
| `GetIdentityFromContext` | Reads the stored context entry and returns a `ContextIdentity` |

`ContextIdentity` is the transport-safe struct used by any code that needs to know who the caller is:

```go
type ContextIdentity struct {
    UserID    uuid.UUID
    UserEmail string
    Username  string
    Role      string
}
```

`Username` and `Role` exist so a service can answer "who am I" from **verified** claims. A browser holding an `HttpOnly` cookie cannot read its own token, and a browser that *can* read its token must not be trusted to decode a role out of it — that is a client deciding its own permissions.

### `IdentityFromRequest`

```go
func (a *Authorization) IdentityFromRequest(r *http.Request) (ContextIdentity, bool)
```

The same extract-and-validate path as `Handler`, but it **reports** the result instead of rejecting the request, and logs nothing. It exists for public endpoints that need to know whether a caller is signed in without treating "signed out" as an error — `SessionHandler` is the built-in user.

---

## authentication

**What it does**

`authentication` builds HTTP handlers on top of the two layers above. It handles the session lifecycle from the user's perspective: cookies in, cookies out.

It holds a reference to an `IdentityManager` (for auth operations), a `TokenHandler` (for reading identity from context in protected handlers), and an `*authorization.Authorization` (for the public handlers that must validate a token themselves).

**HTTP handlers**

| Handler | Route intent | Sets session cookies |
|---|---|---|
| `LoginHandler` | POST — authenticate with email + password | ✅ |
| `RegisterHandler` | POST — sign up with email + password | ❌ — see note below |
| `RefreshAuthHandler` | POST — refresh access token from body or cookie | ✅ |
| `LogoutHandler` | any — clear auth cookies | clears |
| `SessionHandler` | GET — report the session carried by the request | ❌ |
| `StartLoginHandler` | POST — email a passwordless sign-in to an existing user | ❌ |
| `GetVerifyTokenHandler(otpType)` | POST — verify an emailed OTP of the given type | ✅ |
| `AuthLinkHandler` | GET — handle email link callbacks (invite, magic link, recovery, signup), then redirect | ✅ |
| `OAuthStartHandler` | GET — begin a server-side PKCE authorization | ❌ (sets PKCE cookies) |
| `OAuthCallbackHandler` | GET — exchange the authorization code, then redirect | ✅ |
| `ResendVerificationEmailHandler` | POST — resend a confirmation email | ❌ |
| `RequestPasswordResetHandler` | POST — send a password reset email (always 200, to avoid enumeration) | ❌ |
| `ResetPasswordHandler` | POST — set a new password using identity from context | ❌ |
| `ChangePasswordHandler` | POST — verify current password then set a new one | ❌ |
| `DisableAccountHandler` | POST — disable the calling user's account | clears |
| `DeleteAccountHandler` | POST — delete the calling user's account | clears |

`GetVerifyTokenHandler` is a **factory**, not a handler: it returns an `http.HandlerFunc` bound to one `EmailOtpType`, so mount one route per type you support.

> **`RegisterHandler` deliberately sets no cookie.** With email confirmation enabled there is no session to store yet; `GetVerifyTokenHandler(EmailOtpTypeSignup)` establishes it once the address is confirmed. It also answers a duplicate email with the **same** response as a successful signup — a distinguishable response would enumerate registered addresses to an anonymous caller.

**Which handlers need the authorization middleware**

`ResetPasswordHandler`, `ChangePasswordHandler`, `DisableAccountHandler` and `DeleteAccountHandler` all open with `GetIdentityFromContext`. Mounted on a public router they return `401` unconditionally — the context is never populated. Everything else in the table is public by design and carries its own credential in the request.

### Cookies

Two cookies are managed together, both `HttpOnly`, `Secure` in production, `SameSite=Strict` in production and `Lax` in development, with a 7-day max age (`CookieMaxAge`):

| Cookie | Path | Contents |
|---|---|---|
| access token | `/` | the JWT `authorization` validates |
| refresh token | `refreshPath`, default `/` | the token `RefreshAuthHandler` spends |

`SetRefreshPath` scopes the refresh cookie to the single endpoint that can consume it, so it stops riding along on every other request:

```go
authn.SetRefreshPath("/do-auth/refresh")
```

The path must equal the route you mount `RefreshAuthHandler` on. `clearAuthCookie` reads the same field, so logout keeps matching automatically — but a stale hardcoded path elsewhere leaves a cookie logout cannot delete.

> **`SameSite=Strict` requires the browser and the API to be same-site.** If the SPA is served from a different registrable domain than the API, no authenticated request carries its cookie at all, and the failure is silent.

### OAuth (PKCE flow)

`OAuthStartHandler` and `OAuthCallbackHandler` implement the confidential-client flow, so no provider token ever reaches JavaScript:

```
GET  /do-auth/oauth/{provider}         → 302 to Supabase /auth/v1/authorize (code_challenge)
     ↑ generates a PKCE verifier + CSRF state, parks both in short-lived cookies

     … provider consent, Supabase mints the session …

GET  /do-auth/oauth/callback?code=…    → exchanges the code server-side → sets session cookies → 302 to appUrl
```

Details worth knowing before mounting these:

- **`{provider}` is read with `r.PathValue`**, which both `net/http`'s `ServeMux` and chi populate, so the package takes no router dependency. Providers are checked against an allow-list (`OAuthProviderGoogle`, `OAuthProviderApple`); an unchecked provider string interpolated into the authorize URL would be an open redirect.
- **The CSRF `state` travels in `redirect_to`**, not as an `authorize` parameter — Supabase does not round-trip a caller-supplied state, it mints its own for the provider handshake. Your **redirect allow-list entry must therefore tolerate a query string**, e.g. `https://api.example.com/do-auth/oauth/callback*`.
- **The PKCE cookies are `SameSite=Lax` in every environment**, unlike the session cookies. The callback is a cross-site top-level navigation, and `Strict` cookies are not sent on it — every sign-in would fail the state check.
- Every failure redirects to `LoginRedirectConfig.LoginErrorPath` with one generic message; the provider's own error is logged, never rendered.

---

## Practical Example

### Setup

```go
// your service's authorization package — implements TokenHandler for your domain
tokenHandler := myauth.NewTokenHandler()

identities := identityManager.NewSupabaseIdentityManager(
    os.Getenv("SUPABASE_URL"),
    os.Getenv("SUPABASE_ANON_KEY"),
    os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),
)

// ES256 via JWKS, with HS256 still accepted while a legacy secret is configured.
// Pass an empty jwtSecret to accept ES256 only.
authz, err := authorization.NewAuthorizationWithJWKS(
    ctx,
    "token",                    // tokenCookieName — name of the access token cookie
    os.Getenv("JWT_SECRET"),    // legacy HS256 secret; "" disables HS256
    os.Getenv("JWKS_URL"),      // https://<project>.supabase.co/auth/v1/.well-known/jwks.json
    tokenHandler,
    isProduction,
)
if err != nil {
    return fmt.Errorf("build authorization: %w", err)
}

authn := authentication.NewAuthentication(
    identities,
    tokenHandler,
    authz,                      // needed by public handlers that validate the token themselves
    os.Getenv("APP_URL"),       // appUrl — the FRONTEND origin; redirect paths are appended to it
    "token",                    // tokenCookieName
    "rToken",                   // refreshTokenCookieName
    isProduction,
    authentication.LoginRedirectConfig{
        RedirectToTokenLoginAfterMagicLinkFailed: true,
        TokenLoginPath:   "/token-login",        // all four are FRONTEND routes
        LoginErrorPath:   "/",
        AcceptInvitePath: "/register",
        SetPasswordPath:  "/reset-password/new",
    },
    authentication.OAuthConfig{
        SupabaseURL: os.Getenv("SUPABASE_URL"),
        CallbackURL: os.Getenv("API_BASE_URL") + "/do-auth/oauth/callback",
        // CookiePath defaults to "/do-auth/oauth"; it must prefix the callback path
    },
)

// Keep the refresh cookie off every other request.
authn.SetRefreshPath("/do-auth/refresh")
```

> Pass the zero `OAuthConfig` when you do not mount the OAuth routes. `OAuthStartHandler` then refuses and redirects to the error path rather than building a half-formed authorize URL.

### Wiring routes

Note the two groups: public handlers carry their own credential, authenticated ones read the caller from context.

```go
r := chi.NewRouter()

// Public — credential arrives in the body, a cookie, or a query parameter
r.Post("/do-auth/login", authn.LoginHandler)
r.Post("/do-auth/register", authn.RegisterHandler)
r.Post("/do-auth/refresh", authn.RefreshAuthHandler)      // must equal SetRefreshPath
r.Post("/do-auth/logout", authn.LogoutHandler)
r.Get("/do-auth/session", authn.SessionHandler)

// Passwordless: the email carries both a link and a numeric code
r.Post("/do-auth/token-login", authn.StartLoginHandler)
r.Get("/do-auth/link", authn.AuthLinkHandler)
r.Post("/do-auth/verify-otp", authn.GetVerifyTokenHandler(identityManager.EmailOtpTypeEmail))

// Email confirmation after registration
r.Post("/do-auth/verify-email", authn.GetVerifyTokenHandler(identityManager.EmailOtpTypeSignup))
r.Post("/do-auth/resend-verification", authn.ResendVerificationEmailHandler)

r.Post("/do-auth/password/request-reset", authn.RequestPasswordResetHandler)

// chi matches the static "callback" segment before the {provider} wildcard
r.Get("/do-auth/oauth/callback", authn.OAuthCallbackHandler)
r.Get("/do-auth/oauth/{provider}", authn.OAuthStartHandler)

// Authenticated — these read identity from context and 401 without the middleware
r.Group(func(protected chi.Router) {
    protected.Use(authz.Handler)

    protected.Post("/do-auth/password/reset", authn.ResetPasswordHandler)
    protected.Post("/do-auth/password/change", authn.ChangePasswordHandler)
    protected.Post("/do-auth/account/disable", authn.DisableAccountHandler)
    protected.Post("/do-auth/account/delete", authn.DeleteAccountHandler)
})

// Your application routes
r.Route("/api", func(api chi.Router) {
    api.Use(authz.Handler)
    api.Get("/orders", ordersHandler)
})
```

`SessionHandler` is deliberately **not** behind `authz.Handler`. Being signed out is a normal state for a visitor, so it answers `200` with `{"authenticated": false}` rather than `401`; mounted behind the middleware, every anonymous page load would also emit an error log.

```jsonc
// GET /do-auth/session — signed out
{ "authenticated": false }

// GET /do-auth/session — signed in
{ "authenticated": true, "userId": "…", "email": "…", "username": "…", "role": "admin" }
```

### Implementing TokenHandler

This is the only piece you write yourself per service. It translates raw JWT claims into your domain's user struct and stores it in context. The example below is a Supabase-flavoured implementation.

```go
package myauth

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
        Role:     extractRole(claims),
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
//
// Fill Username and Role: SessionHandler reports them to the client, and a client
// that cannot read its own cookie has no other way to learn its role.
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
        Username:  claims.Username,
        Role:      string(claims.Role),
    }, nil
}

func extractRole(claims jwt.MapClaims) string {
    role, _ := claims["user_role"].(string)
    return role
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
        slog.Error("orders rejected", "status", http.StatusUnauthorized, "path", r.URL.Path, "err", err)
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // identity.UserID, .UserEmail, .Username and .Role are now available
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
    ├── Authorization: Bearer header, else the named cookie
    │       └── validateToken (HS256 and/or ES256 via JWKS, then TokenHandler.ValidateToken)
    │               └── TokenHandler.CreateContext → context populated
    └── no token / invalid → 401 Unauthorized
    │
    ▼
Your handler
    └── tokenHandler.GetIdentityFromContext(ctx) → ContextIdentity{UserID, UserEmail, Username, Role}
```

Public endpoints take the same path without the rejection:

```
GET /do-auth/session
    └── authz.IdentityFromRequest(r) → (ContextIdentity, ok) → 200 either way, never logs
```
