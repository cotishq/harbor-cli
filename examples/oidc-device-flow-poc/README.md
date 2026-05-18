# OIDC Device Flow Proof of Concept

This is a small, standalone proof of concept for the `harbor login --sso`
workstream. It demonstrates the OAuth 2.0 Device Authorization Grant flow
without changing harbor-cli production code.

It performs:

- OIDC discovery from an issuer URL
- device authorization request
- user-code login prompt
- RFC 8628 token polling
- handling for `authorization_pending`, `slow_down`, `access_denied`, and
  `expired_token`

Example:

```sh
go run ./examples/oidc-device-flow-poc \
  --issuer-url https://keycloak.example.com/realms/harbor \
  --client-id harbor-cli \
  --scopes "openid profile email offline_access"
```

The production implementation should move this logic behind a package such as
`pkg/auth/oidc`, add encrypted token storage, wire it into `harbor login --sso`,
and use Bearer-token authentication for Harbor API clients.
