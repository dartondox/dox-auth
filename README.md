# dox_auth

Login for Dox apps. It checks an email and a password. It gives back a JWT token for an API, or keeps the login in the session for web pages.

[![pub package](https://img.shields.io/pub/v/dox_auth.svg)](https://pub.dev/packages/dox_auth)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/dartondox/dox-auth/blob/main/LICENSE)

Part of [Dox](https://dartondox.dev), a web backend framework for Dart, like Laravel.
Source code: [github.com/dartondox/dox-auth](https://github.com/dartondox/dox-auth).

## Install

```bash
dart pub add dox_auth
```

To see what is ready and what may still change, read [Status and roadmap](https://dartondox.dev/latest/concepts/status-and-roadmap/).

A new app made with `dox create` does not have it. Add it with the command above.

## Use it

Set it up in a provider:

```dart
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';

class AppAuthProvider extends DoxProvider {
  @override
  void setup() {
    Auth.initialize(AuthConfig(
      defaultGuard: 'web',
      guards: <String, AuthGuard>{
        'web': AuthGuard(
          driver: JwtAuthDriver(
            secret: SecretKey(Env.get('APP_KEY')),
            expiresIn: const Duration(days: 7),
          ),
          provider: AuthProvider(model: () => User()),
        ),
      },
    ));
  }
}
```

Log in, and protect a route:

```dart
String? token = await Auth().attempt(<String, dynamic>{
  'email': 'ada@example.com',
  'password': 'secret',
}); // null when the email or password is wrong

Route.get('/auth/user', <dynamic>[AuthMiddleware(), authController.user]);
```

After `AuthMiddleware`, `req.auth?.user<User>()` is the logged in user.

`Auth` also has `id()` (the primary key of the user, or null), `guest()` (true when nobody is logged in) and `check()` (the same as `isLoggedIn()`).

`Auth().once(credentials)` checks the credentials and gives true or false. It makes no token and does not touch the session. The user is logged in for that `Auth` only, so `auth.user<User>()` works after it.

A route can take more than one guard. `AuthMiddleware(guards: <String>['web', 'api'])` tries each guard in order. The first good login sets `req.auth`. `req.auth?.id()` works with no cast. For a guest, `req.auth` is null.

### Change APP_KEY

New tokens are signed with the current `APP_KEY`. To keep old tokens working after a key change, put the old key in `AppConfig.previousKeys`. The JWT driver checks a token with the current key first, then with each old key. An expired token still fails. Remove the old key once the old tokens have expired.

If the JWT secret is not `APP_KEY`, pass the old secrets to the driver: `JwtAuthDriver(secret: SecretKey(newSecret), previousSecrets: <JWTKey>[SecretKey(oldSecret)])`.

For web pages, use `SessionAuthDriver()` in the guard. It needs `SessionMiddleware`:

```dart
bool ok = await Auth().attemptSession(req, credentials); // false when wrong
Auth().logout(req);

Route.get('/dashboard', <dynamic>[AuthMiddleware(redirectTo: '/login'), pageController.dashboard]);
```

A public page can still know the user. `AuthMiddleware(optional: true)` sets `req.auth` when the login is good, and lets guests through. Then `req.can()` works on that page. A guest, or a bad, expired or revoked token, goes on with `req.auth` null. With the JWT and access token drivers, a database error also goes on as a guest, and it is reported. With the session driver, a database error gives a 500. With `optional: true`, `redirectTo` is not used.

Login and register pages are for guests only. `GuestMiddleware` sends a logged-in user to `redirectTo`, or answers `403` when there is no `redirectTo`:

```dart
Route.get('/posts', <dynamic>[AuthMiddleware(optional: true), postController.index]);
Route.get('/login', <dynamic>[GuestMiddleware(redirectTo: '/dashboard'), pageController.login]);
```

## Features

- JWT driver (`JwtAuthDriver`) with a secret, algorithm, expiry and issuer.
- Session driver (`SessionAuthDriver`) for web pages. Login and logout give the session a new id.
- Access token driver (`AccessTokenAuthDriver`): opaque tokens in a database table, with abilities. You can revoke one token or all tokens of a user.
- `Auth().attempt(credentials)` finds the user and checks the bcrypt hash.
- `Auth().login(user)` gives a token with no password check.
- Custom drivers, like an API key guard. `Auth().setUser(req, user)` sets the user from your own middleware.
- `AuthMiddleware` answers `401` when the user is not logged in. With `redirectTo`, it sends the user to that page instead. With `optional: true`, guests go through too.
- `GuestMiddleware` lets only guests through, for login and register pages.
- More than one guard, like `web` and `admin`, each with its own driver and user model.
- The user is loaded from the database on each request with `dox_orm`.
- Gates and policies for authorization, with the `Can` middleware and `req.can`.

Things to know: a token expires after 1 hour by default. Change it with `expiresIn`.
There is no server list of tokens by default, so you can not cancel one token. Turn on revocation for that (see below).
By default a token holds the user (`toJson()`, hidden fields left out), like in 3.0.2. Anyone can read a token. The safer choice is `JwtAuthDriver(minimalPayload: true)`: the token then holds only the user id (the `sub` claim). Load the user with `req.auth?.user<User>()`, not from the token.
A session login ends with `Auth().logout(req)`.

### Revoke tokens

Revocation is off by default. Then `verifyToken` never reads the cache, like in 3.0.2. Turn it on in the driver:

```dart
JwtAuthDriver(secret: SecretKey(env.appKey), revocation: true, revocationStore: 'auth')
```

Each token has a random id (the `jti` claim). With revocation on, the JWT driver keeps revoked tokens in the app cache (`Cache()` of `dox_core`), so a revoked token stops working at once:

```dart
await Auth().revokeToken(req);     // revoke the bearer token of this request (a JWT logout)
await Auth().revokeAllTokens(id);  // revoke all tokens of a user, eg. after a password change or a ban
await Auth().forgetUser(id);       // drop the user from `userCacheTtl`, eg. after a ban
```

- With revocation off, these three methods throw a `StateError`, so no one thinks a token is revoked when it is not.
- `Auth().logout(req)` is the session logout, like in 3.0.2. On a JWT guard it throws. For a JWT, use `revokeToken`.
- A revoked token stays on the deny-list only until it expires.
- `revokeAllTokens` keeps tokens made after the call. A token made in the same second as the call also still works.
- Give auth its own store, and never flush it. Pick it with `JwtAuthDriver(revocationStore: 'auth')`, for example a `redis` store with its own prefix. A flush of this store (`Cache().flush()`), or a `memory` store with `max_size` that drops old keys, brings revoked tokens back until they expire. With no `revocationStore`, the default app store is used.
- Cost: `verifyToken` reads this store on every request, also with `userCacheTtl`. It is one `many()` call: one round trip on `redis` and `memory`. On the `file` store (the default) it is 2 or 3 file reads per request. Use `memory` for one isolate, or `redis` for many isolates or servers. A `memory` store is seen by one isolate only.
- When the store can not be read, the token is checked like before (signature and `exp`), and a warning is printed once. A cache outage does not log everyone out, but revoked tokens work until the store is back.
- Tokens made before 3.1.0 have no `jti`. They still work until they expire, so an upgrade logs no one out. `revokeToken` can not put them on the deny-list. `revokeAllTokens` stops them when they have an `iat` claim (tokens from `JwtAuthDriver` do).
- The `revokeAllTokens` time comes from the server clock. Keep server clocks in sync (NTP). If the server that made a token has a clock that is ahead, its old tokens can pass the check.
With the default `cookie` session driver, all session data sits in the cookie. So an old copy of the cookie still works after logout. If logout must really end old cookies, use the `cache` session driver, like `SessionConfig(driver: 'cache', store: 'redis')`.

### Access tokens

Opaque API tokens that you can revoke at any time, like AdonisJS access tokens or Laravel Sanctum. It is opt-in: session and JWT guards do not change.

A token looks like `oat_12.<secret>`. The table keeps only a SHA-256 hash of the secret. The plain token is shown once, when you make it. A token works until it expires or you revoke it.

#### 1. Guard

```dart
'api': AuthGuard(
  driver: AccessTokenAuthDriver(), // table: 'auth_access_tokens', expiresIn: null (no end), type: the guard name
  provider: AuthProvider(model: () => User()),
),
```

#### 2. Table

Run `dox auth:tokens-table`. It writes a migration in `db/migration` that makes the `auth_access_tokens` table. Then run `dox migrate`.

```bash
dox auth:tokens-table --users-table=users
dox migrate
```

`auth:tokens-table` is a [package command](https://dartondox.dev/digging-deeper/package-commands/) of `dox_auth`. It does not overwrite: when a `create_access_tokens_table` migration is already there, it prints so and stops.

Flags:

- `--uuid`: for users with uuid ids (`uuidIds: true`).
- `--string-ids`: for users with text ids (`stringIds: true`).
- `--users-table=users`: adds a foreign key to this table (`usersTable:`).
- `--users-key=uid`: the key column of the users table, when it is not `id` (`usersKey:`).

For other options, like `table:`, edit the migration file. With `--users-table=users`, the migration it writes looks like this. You can also write it by hand. `AccessTokenTables` makes the table.

`db/migration/2026_11_02_000000000_create_access_tokens_table.dart`:

```dart
// ignore_for_file: file_names
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_migration/dox_migration.dart';

/// The auth_access_tokens table of dox_auth.
class CreateAccessTokensTable extends Migration {
  @override
  Future<void> up(Schema schema) async {
    await AccessTokenTables.up(schema, usersTable: 'users');
  }

  @override
  Future<void> down(Schema schema) async {
    await AccessTokenTables.down(schema);
  }
}
```

Options of `AccessTokenTables.up`:

- `table: 'tokens'`: when the driver uses another table (`AccessTokenAuthDriver(table: 'tokens')`), pass the same name.
- `stringIds: true`: for users with text ids. Set `AccessTokenAuthDriver(stringIds: true)` too. By default `tokenable_id` is an unsigned big int, like Sanctum and AdonisJS.
- `uuidIds: true`: for users with uuid ids. `tokenable_id` is then a uuid column (`UUID` on Postgres), so `usersTable:` works with a uuid id. Set `AccessTokenAuthDriver(uuidIds: true)` too. A uuid is kept and compared in lower case, like Postgres does, so keep uuids in lower case in the users table.
- `usersTable: 'users'`: adds a foreign key from `tokenable_id` to `users.id`, with cascade delete. Then the tokens of a deleted user are deleted too. The two id columns must have the same type. Use `usersKey: 'uid'` when the key of the users table is not `id`. If you have more than one user model (like users and admins), give each model its own token table, with `table:` on the driver and in the migration. With one shared table, the foreign key fails for admin tokens, and deleting a user also deletes the tokens of the admin with the same id.

The migration makes the table on the default connection. If the driver uses another connection (`AccessTokenAuthDriver(connection: 'other')`), make the table on that connection.

#### 3. Use it

```dart
// log in: gives a new token with all abilities, or null
String? token = await Auth(guard: 'api').attempt(credentials);

// or make one for a user
AccessToken token = await Auth(guard: 'api').createAccessToken(
  user,
  name: 'cli', // at most 255 characters
  abilities: <String>['posts:read'], // default: ['*'] (all)
  expiresIn: const Duration(days: 30), // default: the driver expiresIn
);
return <String, dynamic>{'token': token.value}; // shown once

await Auth(guard: 'api').accessTokens(user);            // list, newest first
await Auth(guard: 'api').revokeAccessToken(user, id);   // false when not a token of this user
await Auth(guard: 'api').revokeAllAccessTokens(user);   // eg. after a password change
await Auth(guard: 'api').revokeToken(req);              // logout: revoke the token of this request
await Auth(guard: 'api').pruneExpiredAccessTokens();    // delete expired tokens, eg. from a scheduled job

// renew: a new token, the old one works 2 more minutes
AccessToken next = await auth.rotateAccessToken(
  auth.currentAccessToken!,
  grace: const Duration(minutes: 2),
);

// change what a token can do, eg. after a two-step code
await auth.setAccessTokenAbilities(auth.currentAccessToken!, <String>['2fa']);
```

Rotate (renew) a token:

- The new token gets the user, name and abilities of the old token's row. `expiresIn: null` gives the driver `expiresIn` (no end when that is null too).
- A token can be rotated only once. A second rotate of the same old token throws an `UnAuthorizedException` (a 401) and makes no token, also in the grace time. When two rotates of one token run at the same time, only one works.
- `grace` is how long the old token still works, so requests that are on the way do not fail. Default: it ends now. A larger `grace` gives a stolen old token more time to be used. It can not make new tokens.
- A revoked or expired token throws an `UnAuthorizedException` too. A token of another guard, a negative `grace` or a token without its `user` throws an `ArgumentError`.
- Each rotate gives a full new life. So a client that rotates again and again stays logged in forever. If you want a limit, check `token.createdAt` of the first login yourself, or set `expiresIn`.
- `rotateAccessToken` needs the `rotated_at` column (see below). It runs in one transaction: when it fails, nothing is changed.

`setAccessTokenAbilities` throws an `UnAuthorizedException` when the token is revoked, and an `ArgumentError` for a token of another guard.

**Existing token tables:** tables made before this version have no `rotated_at` column. Everything works without it, except `rotateAccessToken`: it throws a `StateError` that names the column. To use it, add the column in a new migration:

```dart
await schema.table('auth_access_tokens', (Table t) {
  t.dateTimeTz('rotated_at').nullable();
});
```

In a route behind `AuthMiddleware`, `(req.auth as Auth).revokeToken(req)` uses the token that was already checked, so it does not check it again.

The client sends `Authorization: Bearer oat_12.<secret>`. Protect the route with `AuthMiddleware(guard: 'api')`. Then check abilities:

```dart
Auth auth = req.auth as Auth;
if (!auth.tokenCan('posts:write')) throw ForbiddenHttpException();
auth.currentAccessToken; // the AccessToken of this request
```

- A token fails (401) when its format is bad, the secret is wrong, it is expired, it was revoked (the row is deleted), its user is gone, it has another type, or it was made for a guard with another user table. A database error also fails the check, and it goes to `AppConfig.exceptionHandler`. With `AccessTokenAuthDriver(throwOnError: true)` the error is thrown, so the client is not logged out by a short database problem. This is also true for a token row that can not be read, or a wrong guard setup. The error goes to your `ExceptionHandler`, and the default answer is a 500. To answer 503, override `render`:

  ```dart
  class AppExceptionHandler extends ExceptionHandler {
    @override
    dynamic render(Object error, HttpRequest req) {
      // PgException: dox_postgres_native. MysqlException: dox_mysql_native.
      if (error is PgException) {
        return HttpStatusException(503, headers: {'retry-after': '5'});
      }
      return super.render(error, req);
    }
  }
  ```
- `tokenable_type` is the table name of the user model. If you rename the users table, the old tokens stop working.
- Each token has a `type`. By default it is the guard name. A token works only on a guard with the same type, so two access token guards do not take each other's tokens. If you rename a guard, set `AccessTokenAuthDriver(type: 'old-name')` to keep its tokens working.
- Pass a user of the guard's model. For admins, use `Auth(guard: 'admin').createAccessToken(admin)`. A user of another model throws an `ArgumentError`.
- When you delete a user, call `revokeAllAccessTokens(user)` too, or use `usersTable:` in the migration. Then old tokens can never match a new user with the same id.
- `tokenCan` is false when there is no access token, so a session or JWT login never passes it.
- `last_used_at` is written at most once a minute per token. If this write fails, the error is reported and the request goes on.
- `Auth().login(user)` throws a `StateError` with this driver. Use `createAccessToken`.
- Expired tokens stay in the table until you call `pruneExpiredAccessTokens()`.
- On MySQL, `expires_at` is kept to the second: MySQL rounds the time. So a token can stop working up to half a second before or after its exact time.

### Login throttle

Limit failed logins per account and ip. It is off by default. Turn it on in the `register` or `boot` of a provider. `Auth.throttle` is a static, so each isolate has its own copy. If you set it in `main()` before the server starts, only the first isolate throttles.

```dart
Auth.throttle = LoginThrottle(maxAttempts: 5, decay: Duration(minutes: 1));

// JWT: pass the client ip
String? token = await Auth(ip: req.ip()).attempt(credentials);

// session: the ip comes from the request
bool ok = await Auth().attemptSession(req, credentials);
```

- After `maxAttempts` failed logins for the same login field (eg. the email) and ip, the next try throws `LoginThrottledException` (429) until `decay` has passed. `retryAfter` says how long to wait.
- A good login clears the count. The login field is trimmed and lower case, so `A@x.com` and `a@x.com` share one count.
- The counts live in the app cache. Pick a store with `LoginThrottle(store: 'redis')`. Use a shared store like `redis` for many isolates or servers.
- Without an ip, `attempt` counts per account only. Then anyone can lock an account for `decay`, so pass the ip.
- `attemptSession` sends a `Retry-After` header with the 429. `attempt` has no request, so catch `LoginThrottledException` and set the header from `retryAfter` if you need it.
- Known limit, parallel tries: the limit is checked before the failed try is counted. So tries that run at the same time all pass the check before any of them is counted. A burst of parallel wrong logins can all run, far past `maxAttempts`. In a test, 50 parallel wrong logins with `maxAttempts: 5` all ran. The limit works for tries that come one after another, like a person or a simple script. To stop fast parallel guessing, also put `RateLimit` on the login route.
- Known limit, lost counts: a failed try reads the count, adds one, and writes it back. Two failed tries at the same time can read the same count and both write the same number, so one count is lost. This can happen with any store, even in one isolate. It happens more with many isolates or servers on one Redis store.
- With more than one login field (eg. email and username), each set of fields that a client sends gets its own count.

### Password hash cost

Passwords use bcrypt with cost 10 by default. Each step up doubles the time of a login. To raise it, set the cost for new hashes and tell the driver, so a login for an unknown email takes as long as a wrong password:

```dart
Hash.rounds = 12;
JwtAuthDriver(secret: SecretKey(env.appKey), hashRounds: 12);
SessionAuthDriver(hashRounds: 12);
```

Old hashes keep their own cost, so they still work. Hash them again on the next good login:

```dart
if (Auth.needsRehash(user.password)) {
  user.password = Hash.make(password);
  await user.save();
}
```

`Auth.hashCost(hash)` gives the cost of a hash. `Auth.needsRehash(hash, rounds: 12)` checks another cost.

### Check a login with no request

For code with no request, like a Socket.IO login:

```dart
User? user = await Auth(guard: 'api').userFromToken(token);   // a JWT or an access token, no `Bearer ` prefix
User? user = await Auth(guard: 'web').userFromSession(session); // from SessionMiddleware().fromCookie(value)
```

`userFromToken` runs the same checks as a request with a `Bearer` header. With `AccessTokenAuthDriver`, `currentAccessToken` and `tokenCan` work after it. A missing, bad, expired, revoked or changed token gives `null`. `userCacheTtl` is a cache, not a check: with it on, a deleted or banned user can still connect until the cache time ends, unless `forgetUser` runs.

## Custom guard (API key)

You can check the user in your own way, like an API key in the header.
Write a driver: extend `AuthDriver` and return the user from `verifyToken`.
`AuthMiddleware` and `req.auth` then work as with the other drivers.

```dart
/// `Authorization: Bearer <api key>` gives the user with this key.
class ApiKeyAuthDriver extends AuthDriver {
  @override
  Future<Model<dynamic>?> verifyToken(IDoxRequest req, String guard) async {
    String header = req.header('Authorization') ?? '';
    if (!header.startsWith('Bearer ')) return null;
    Model<dynamic> model = AuthEngine().guard(guard).provider.model();
    return await model.where('api_key', header.substring(7).trim()).getFirst();
  }

  /// no password login for this guard
  @override
  Future<Model<dynamic>?> attempt(Map<String, dynamic> credentials, String guard) async => null;

  /// no token to make: the key is the token
  @override
  String? createToken(Map<String, dynamic>? userPayload, String guard) => null;
}
```

Add it as a guard, and use the guard in the route:

```dart
'api': AuthGuard(
  driver: ApiKeyAuthDriver(),
  provider: AuthProvider(model: () => User()),
),

Route.get('/api/me', <dynamic>[AuthMiddleware(guard: 'api'), (DoxRequest req) => req.auth?.user<User>()]);
```

Store a hash of the key, not the key itself, and compare the hash.

If you already have your own middleware, set the user with `Auth().setUser(req, user)`.
It needs no token and no password check. `req.auth` then gives this user:

```dart
User? user = await keys.userForKey(key);
if (user == null) throw UnAuthorizedException();
Auth(guard: 'api').setUser(req, user);
return req;
```

## Authorization (gates and policies)

Auth says who the user is. Gates and policies say what the user may do.

A gate is one rule. The types come from the function:

```dart
Gate.define('update-post', (User user, Post post) => post.userId == user.id);
Gate.define('create-post', (User user, _) => user.verified == true); // no subject

await Gate.allows(user, 'update-post', post); // true or false
await Gate.authorize(user, 'update-post', post); // 403 when denied
```

A policy holds the rules of one model:

```dart
class PostPolicy extends Policy<User, Post> {
  bool create(User user) => user.verified == true;
  bool update(User user, Post post) => post.userId == user.id;

  @override
  Map<String, Function> get abilities => <String, Function>{
    'create': create,
    'update': update,
  };
}

Gate.policy<Post>(PostPolicy());
await Gate.allows(user, 'update', post);
await Gate.allows(user, 'create', Post); // no model: pass the type
```

In a controller, `req.can`, `req.cannot` and `req.authorize` use the user of `req.auth`.
On a route, use the `Can` middleware after `AuthMiddleware`.
A guest gets `401`. A user who may not do it gets `403`.

```dart
await req.authorize('update', post);

Route.post('/posts', <dynamic>[AuthMiddleware(), Can('create', subject: Post), postController.store]);
Route.put('/posts/{post}', <dynamic>[AuthMiddleware(), Can('update', param: 'post'), postController.update]);
```

With `param`, the subject is the value of `Route.bind` for that route param.

More:

- A check gives a `bool` or a `GateResponse`. `GateResponse.deny('Why')` sets the message of the 403.
- `Gate.before((User user, String ability) => user.isAdmin ? true : null)` decides before every check. `Gate.after` sees every answer, eg. to log it.
- `Gate.any` and `Gate.all` check a list of abilities.
- A guest is denied, unless the user type is nullable, like `(User? user, Post post)`.
- Gates and policies are kept per isolate. Dox runs many isolates, so register them in a `DoxProvider` `setup()`. It runs in every isolate.

## Documentation

- [Authentication](https://dartondox.dev/latest/security/authentication/)
- [Session](https://dartondox.dev/latest/the-basic/session/)
- [Guide: JWT auth](https://dartondox.dev/latest/guides/jwt-auth/)
- [API reference](https://pub.dev/documentation/dox_auth/latest/)

## License

MIT. See [LICENSE](https://github.com/dartondox/dox-auth/blob/main/LICENSE).
