## Unreleased

- Fix: after `once()` or `attempt()` logged in another user, `revokeToken()` could still revoke the old access token of the request. `once()` and `attempt()` now drop that token too.
- Fix: `once()` and `attempt()` kept the access token of the request. After a login of another user, `tokenCan()` and `currentAccessToken` still used the old token. They now drop it.
- Tests: `AuthMiddleware` with several guards checks which guard let the user in, and a bad bearer token with a good session. `once()` counts in the login throttle and leaves the session empty.

## 3.1.0

No breaking change. Apps on 3.0.2 work the same with no code change, and no user is logged out. The new, safer features are opt-in.

- New `AuthMiddleware(guards: ['web', 'api'])`: tries several guards in order, like Laravel `auth:web,api`. The first good login sets `req.auth`. `AuthMiddleware(guard: ...)` works as before. Setting both, or an empty list, throws an `ArgumentError`.
- New `Auth().check()`: the same as `isLoggedIn()`, with the Laravel name.
- New `Auth().once(credentials)`: checks the credentials and gives true or false, like Laravel `Auth::once`. The user is logged in for this `Auth` only: no token, no session. The throttle counts it like `attempt`. `attempt()` still gives a token.
- The error of `Auth().logout(req)` on a JWT or access token guard now says to use `revokeToken()`. `logout` still throws there: a silent no-op would leave the token working.
- New `Auth().id()`: the primary key of the logged-in user, or null for a guest. It works when the key is hidden from `toJson()`. New `Auth().guest()`: true when nobody is logged in.
- New `AuthMiddleware(optional: true)`: a good login sets `req.auth`, and guests go through too, so `req.can()` works on a public page. A bad, expired or revoked token is a guest. With the JWT and access token drivers, a database error is a guest too, but it is reported. With the session driver, a database error gives a 500. `redirectTo` is not used with `optional: true`. The default (`optional: false`) does not change.
- New `GuestMiddleware(guard:, redirectTo:)`: lets only guests through, for login and register pages, like the Laravel `guest` middleware. A logged-in user goes to `redirectTo`, or gets a 403 (`already_logged_in`).
- New, opt-in: access tokens, like AdonisJS access tokens or Laravel Sanctum. Session and JWT guards do not change.
  - New `AccessTokenAuthDriver`. A token looks like `oat_<id>.<secret>`. The table keeps only a SHA-256 hash of the secret, checked in constant time. The plain token is shown once.
  - New `AccessTokenTables.up(schema)` and `down(schema)` for a migration. The default table is `auth_access_tokens`. `tokenable_id` is an unsigned big int. `stringIds: true` (on the table and the driver) makes it text, for users with text ids (compared exactly). For uuid users, use `uuidIds: true` instead (see below). `usersTable:` adds a foreign key with cascade delete (`usersKey:` for a key that is not `id`). There is an index on `expires_at`.
  - Each token has a `type` (default: the guard name, or `AccessTokenAuthDriver(type: ...)`). A token works only on a guard with the same type.
  - The time columns are `DATETIME` on MySQL, so a token can expire after 2038.
  - New `Auth().createAccessToken(user, name:, abilities:, expiresIn:)`, `accessTokens(user)`, `revokeAccessToken(user, id)`, `revokeAllAccessTokens(user)`, `pruneExpiredAccessTokens()`, `tokenCan(ability)` and `currentAccessToken`.
  - `Auth().attempt(credentials)` gives an access token with this driver. `Auth().revokeToken(req)` revokes the access token of the request.
  - A bad, wrong, expired or revoked token gives no user (401). A database error does too, and it is reported.
  - `Auth().userFromToken(token)` also checks an access token, for code with no request (like Socket.IO). Then `currentAccessToken` and `tokenCan` work. The driver method is `check(token, guard)` (an instance method).
  - `AccessTokenTables.up(schema, uuidIds: true)` and `AccessTokenAuthDriver(uuidIds: true)`: `tokenable_id` is a uuid column, so a foreign key to uuid users works on Postgres. A uuid is kept and compared in lower case.
  - The user must be a model of the guard. `createAccessToken`, `accessTokens`, `revokeAccessToken` and `revokeAllAccessTokens` throw an `ArgumentError` for a user of another model (eg. an admin on the users guard).
  - Two `Authorization` headers give no user (401), not an error.
  - A token `name` over 255 characters throws an `ArgumentError`, before anything is written.
  - A failed `last_used_at` write is reported, and the request goes on.
- New: `dox auth:tokens-table` writes a migration for the access tokens table in `db/migration`. It calls `AccessTokenTables.up` and `AccessTokenTables.down`. Flags: `--uuid`, `--string-ids`, `--users-table=<table>` and `--users-key=<column>`. It does not overwrite: when a `create_access_tokens_table` migration is already there, it prints so and exits with code 1. It is a package command (`dox: commands:` in pubspec.yaml), so it needs a `dox` CLI that finds package commands. The same flag twice is an error: it writes nothing and exits with code 1. `--users-key` without `--users-table` prints a warning (it does nothing alone).
- Needs dox_core with `package:dox_core/command.dart`.
- New `AuthDriver.reportError(error, stackTrace)`: the JWT driver now uses it to report errors.
- New dependency: `crypto`.
- By default a JWT holds the same data as in 3.0.2: the user (`toJson()`, hidden fields left out), plus `iat`, `exp` and a new `jti`. A front end that reads user fields from the token still works.
- Security, opt-in: `JwtAuthDriver(minimalPayload: true)` puts only the user id (the `sub` claim) in new tokens. This is the safer choice: anyone can read a JWT payload, and a small token is cheaper to send. Load the user with `req.auth?.user<User>()`, not from the token.
- The user id comes from the primary key, like in 3.0.2. Only a small token (a `jti` and no primary key) reads `sub`. A user column named `sub` (eg. from an OAuth login) is never taken as the id.
- Tokens made before this version (no `jti`) work exactly like in 3.0.2.
- Security, opt-in: JWT revocation with `JwtAuthDriver(revocation: true)`. Off by default: then `verifyToken` does no cache read, like in 3.0.2.
  - New `Auth().revokeToken(req)`: a JWT logout. It revokes the bearer token of the request until it expires, also after `userFromToken` on the same `Auth`.
  - New `Auth().revokeAllTokens(id)`: all tokens of the user made before the current second stop working (eg. after a password change or a ban). `iat` is in whole seconds, so a token made in the same second as the call still works. An old token with an `iat` claim is stopped too (tokens from `JwtAuthDriver` have one). An old token with no `iat` works until it expires.
  - New `Auth().forgetUser(id)`: drops the user from the `userCacheTtl` cache on all isolates and servers that share the cache.
  - With revocation off, these three methods throw a `StateError`, so no one thinks a token is revoked when it is not.
  - `revokeToken` on an old token (no `jti`) does nothing: it can not go on the deny-list.
  - New optional `JwtAuthDriver(revocationStore: ...)` picks the cache store. Give auth its own store and never flush it: a flush, or a full `memory` store with `max_size`, brings revoked tokens back. Use a shared store like `redis` with many isolates or servers.
  - With revocation on, `verifyToken` reads this store on every request, also with `userCacheTtl`. On the default `file` store this is 2 or 3 file reads per request. Use `memory` for one isolate, or `redis` for many. If the store can not be read, the token is checked like in 3.0.2 (signature and `exp`), and a warning is printed once, so a cache outage does not log everyone out.
- New `Auth(guard: 'api').userFromToken(token)`: checks a JWT with no request, for example in a Socket.IO `findUser`. It runs the same checks as a `Bearer` header (signature, algorithm, guard, `exp`, revocation) and uses the same code. With `userCacheTtl` on, a deleted or banned user is still found until the cache time ends, unless `forgetUser` runs. A null, bad, expired, revoked or changed token gives null. Needs a guard with `JwtAuthDriver`. The driver method is `JwtAuthDriver.userFromToken(token, guard)`.
- New `Auth(guard: 'web').userFromSession(session)`: the user that is logged in to a session, with no request. Load the session with `SessionMiddleware().fromCookie(value)` of dox_core. Needs a guard with `SessionAuthDriver`. The driver method is `SessionAuthDriver.userFromSession(session, guard)`.
- `Auth().logout(req)` is not changed: it is the session logout, like in 3.0.2.
- Fix: the `Bearer` prefix of the `Authorization` header is matched in any case, so `bearer xyz` works. New `JwtAuthDriver.bearerToken(req)` reads the token.
- Fix: JWT `verifyToken` no longer hides unexpected errors. A database outage or a bad config still gives no user (a 401), like in 3.0.2, but the error now goes to `AppConfig.exceptionHandler.report` (or stderr before Dox is set up), so you can see it. A bad, changed or expired token is still quiet.
- Fix: a request with two `Authorization` headers is a normal 401 for the JWT and access token drivers. It is no longer reported as an error, so it does not fill the error tracker. `JwtAuthDriver.bearerToken(req)` gives null for it.
- Security, opt-in: login throttle. `Auth.throttle = LoginThrottle(maxAttempts: 5, decay: Duration(minutes: 1))` limits failed `attempt` and `attemptSession` logins per login field and ip, with the app cache. Too many tries throw `LoginThrottledException` (429). `attemptSession` also sends `Retry-After`. Off by default, so nothing changes. New optional `Auth(ip: req.ip())` gives the ip to `attempt`.
- New: `Auth.needsRehash(hash)` is true when a password hash was not made with the cost of `Hash.rounds` (or `rounds:`). `Auth.hashCost(hash)` reads the cost of a hash. The default cost stays 10. The README shows how to raise it and hash old passwords again on login.
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
