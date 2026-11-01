## Unreleased

No breaking change for code that calls dox_auth. Apps on 3.0.2 keep working, and no user is logged out.

- By default a JWT holds the same data as in 3.0.2: the user (`toJson()`, hidden fields left out), plus `iat`, `exp` and a new `jti`. A front end that reads user fields from the token still works.
- Security, opt-in: `JwtAuthDriver(minimalPayload: true)` puts only the user id (the `sub` claim) in new tokens. This is the safer choice: anyone can read a JWT payload, and a small token is cheaper to send. Load the user with `req.auth?.user<User>()`, not from the token.
- The user id comes from the primary key, like in 3.0.2. Only a small token (a `jti` and no primary key) reads `sub`. A user column named `sub` (eg. from an OAuth login) is never taken as the id.
- Tokens made before this version (no `jti`) still work until they expire, exactly like in 3.0.2.
- Security: a JWT can now be revoked. Each new token has a random `jti`. The JWT driver keeps revoked tokens in the app cache.
  - `Auth().logout(req)` now works on a JWT guard: it revokes the bearer token of the request until it expires. Before, it threw a `StateError` on a JWT guard.
  - `logout` now returns `Future<void>` and takes an `IDoxRequest`. Every 3.0.2 call still compiles, and a session logout still happens at once, also without `await`. `await` it on a JWT guard to be sure the token is revoked. Two small changes: a class that `extends Auth` and overrides `logout` must use the new signature, and the `unawaited_futures` lint now warns on a call with no `await`.
  - New `Auth().revokeAllTokens(id)`: all tokens of the user made before now stop working (eg. after a password change or a ban). An old token with an `iat` claim is stopped too (tokens from `JwtAuthDriver` have one). An old token with no `iat` works until it expires.
  - Logout on an old token (no `jti`) does nothing extra, like before: it can not go on the deny-list.
  - New `Auth().forgetUser(id)`: drops the user from the `userCacheTtl` cache on all isolates and servers that share the cache.
  - New optional `JwtAuthDriver(revocationStore: ...)` picks the cache store. Give auth its own store and never flush it: a flush, or a full `memory` store with `max_size`, brings revoked tokens back. Use a shared store like `redis` with many isolates or servers.
  - `verifyToken` reads this store on every request, also with `userCacheTtl`. On the default `file` store this is 2 or 3 file reads per request. Use `memory` for one isolate, or `redis` for many. If the store can not be read, the token is checked like in 3.0.2 (signature and `exp`), and a warning is printed once, so a cache outage does not log everyone out.
- `AuthDriver.createToken` gets `user.toJson()`, like in 3.0.2. When the primary key is hidden, the id is added as `sub`.

## 3.0.2

- New: gates and policies, for what a user may do.
  - `Gate.define('update-post', (User user, Post post) => ...)` adds a rule. The user and subject types come from the function.
  - `Policy<User, Post>` holds the rules of one model. Add it with `Gate.policy<Post>(PostPolicy())`.
  - `Gate.allows`, `denies`, `authorize` (403 when denied), `inspect`, `any` and `all`.
  - `Gate.before` and `Gate.after` hooks. `Policy.before` for one policy.
  - `GateResponse.deny('reason')` gives the message of the 403.
  - A guest is denied, unless the user type is nullable.
  - `req.can`, `req.cannot` and `req.authorize` use the user of `req.auth`.
  - `Can('update', param: 'post')` middleware. A guest gets 401, a denied user gets 403. With `param`, the subject is the `Route.bind` value.

## 3.0.1

- `JwtAuthDriver` keeps old tokens working after an `APP_KEY` change. When a token has a wrong signature, it tries each old key from `AppConfig.previousKeys`. New tokens are signed with the current key only. An expired token or a bad claim still fails at once.
- New `previousSecrets` option on `JwtAuthDriver`, for a JWT secret that is not `APP_KEY`.
- Needs dox_core 3.0.1.

## 3.0.0

- The first stable release.
- The package now lives in its own repo: [dartondox/dox-auth](https://github.com/dartondox/dox-auth). Nothing changes for users: same package name, same API.

## 3.0.0-rc.1

- Breaking: `JwtAuthDriver` no longer signs with the `SecretKey` text as it is. The HMAC key is made from it with HKDF-SHA256 and the label `dox:jwt`. Existing tokens become invalid after this version. Users must log in again. `driver.signingKey` gives the key, for another service that checks the tokens.
- Security: `JwtAuthDriver.verifyToken` accepts only the configured `algorithm`. A token with another algorithm in its header is rejected.
- Security: `attempt` only puts a string or a number into the user query. A map or a list as the email (or another identifier) fails the login.
- `AuthMiddleware` and `Auth.setUser` set `req.auth` directly. They no longer put the auth into the request input.
- `UnAuthorizedException` takes a `dynamic message`, so a map message works.
- `APP_ENV=testing` is treated like `test` for the short secret check: only a warning.

## 3.0.0-alpha.17

- Uses dox_orm 3.0.0-alpha.12.

## 3.0.0-alpha.16

- Version bump only, to match the other packages.

## 3.0.0-alpha.15

- Docs: the README and the example set up auth in an `AppAuthProvider` that extends `DoxProvider`.

## 3.0.0-alpha.14

- New: `Auth().setUser(req, user)` sets the logged-in user on `req.auth`, with no token and no password check. Use it in your own auth middleware, like an API key check.
- Docs: how to write a custom guard. Extend `AuthDriver`, return the user from `verifyToken`, and use `AuthMiddleware(guard: 'api')`. The README and the authentication page show an API key example.
- Fix: importing `dox_auth` and `dox_core` together gave an "ambiguous import" error for `AUTH_REQUEST_KEY`. `dox_auth` no longer has its own copy. The one in `dox_core` is used.

## 3.0.0-alpha.13

- Version bump only, to match the other packages.

## 3.0.0-alpha.12

- New: `SessionAuthDriver` keeps the login in the session, for web pages. Use `Auth().attemptSession(req, credentials)`, `Auth().loginSession(req, user)` and `Auth().logout(req)`. Login and logout give the session a new id. Needs `SessionMiddleware`.
- New: `AuthMiddleware(redirectTo: '/login')` sends a guest to that page instead of a 401.
- Docs: with the default `cookie` session driver, an old copy of the cookie still works after logout. The README now says to use the `cache` driver when logout must end old cookies.
- Change: the password check of `attempt` moved to `AuthDriver.checkCredentials`, so all drivers share it.

## 3.0.0-alpha.11

- Version bump only, to match the other packages.

## 3.0.0-alpha.10

- Version bump only, to match the other packages.

## 3.0.0-alpha.9

- Version bump only, to match the other packages.

## 3.0.0-alpha.8

- Security: a JWT secret (`SecretKey`) shorter than 32 bytes stops the app with an `ArgumentError` when `APP_ENV` is not `development`, `local` or `test`. In those envs it prints one warning line. Make a key with `dox key:generate` or `openssl rand -hex 32`.
- `Hash` now comes from `dox_core`. dox_auth had its own copy. `package:dox_auth/src/hash.dart` re-exports it. No change in behaviour. dox_auth now depends on dox_core.

## 3.0.0-alpha.7

- Perf: `attempt` runs bcrypt in another isolate (`Isolate.run`). Before, each login blocked the server isolate for the whole hash.
- Perf: the dummy hash for unknown users is made when the driver is created, in another isolate. Before, the first login paid for two hashes.
- New: `JwtAuthDriver(hashRounds: 10)`. Set it to the bcrypt cost of your stored hashes.
- New: `JwtAuthDriver(userCacheTtl: ...)`. Keeps the user of a token in memory for this time, so `verifyToken` does not run `find(id)` on every request. Off by default.
- Security: `JwtAuthDriver` throws `ArgumentError` when the `SecretKey` is empty. Before, an app with no `APP_KEY` signed tokens with an empty key, so anyone could make a token for any user.
- Security: `attempt` runs bcrypt also when no user is found, or when the user has no password. Before, an unknown email answered much faster than a wrong password, so the time told which emails have an account.

## 3.0.0-alpha.6

- Version bump only, to match the other packages.

## 3.0.0-alpha.5

- Breaking: `JwtAuthDriver.expiresIn` is 1 hour by default. Before, it was `null`, and tokens never expired.
- New: named guards work. Use `Auth(guard: 'admin')` and `AuthMiddleware(guard: 'admin')`. Before, only `defaultGuard` was used.
- A token keeps its guard name in the `aud` claim. A token from one guard does not work on another guard.
- `verifyToken` checks the `iss` claim when `issuer` is set.
- Breaking: `AuthDriver` methods get the guard name as a new parameter. `AuthEngine().guard(name)` replaces `AuthEngine().driver` and `AuthEngine().provider`.

## 3.0.0-alpha.4

- Version bump only, to match the other packages.

## 3.0.0-alpha.3

- Version bump only, to match the other packages.

## 3.0.0-alpha.2

- Needs Dart 3.13 or newer.
- All dependencies updated to their latest versions.
- `dart_jsonwebtoken` 3.4 (`pointycastle` 4).

## 3.0.0-alpha.1

- Version 3 of Dox. All Dox packages now share one version.
- Needs Dart 3.6 or newer.
- See the [release notes](https://github.com/dartondox/dox/pull/112) for all main changes.
- Uses `dox_orm` (was `dox_query_builder`).
- `dart_jsonwebtoken` 3.

## 2.0.0

- Compatible for core version 2.0.

## 1.0.1

- Initial version.
