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

A new app made with `dox create` already has it.

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

### Change APP_KEY

New tokens are signed with the current `APP_KEY`. To keep old tokens working after a key change, put the old key in `AppConfig.previousKeys`. The JWT driver checks a token with the current key first, then with each old key. An expired token still fails. Remove the old key once the old tokens have expired.

If the JWT secret is not `APP_KEY`, pass the old secrets to the driver: `JwtAuthDriver(secret: SecretKey(newSecret), previousSecrets: <JWTKey>[SecretKey(oldSecret)])`.

For web pages, use `SessionAuthDriver()` in the guard. It needs `SessionMiddleware`:

```dart
bool ok = await Auth().attemptSession(req, credentials); // false when wrong
await Auth().logout(req);

Route.get('/dashboard', <dynamic>[AuthMiddleware(redirectTo: '/login'), pageController.dashboard]);
```

## Features

- JWT driver (`JwtAuthDriver`) with a secret, algorithm, expiry and issuer.
- Session driver (`SessionAuthDriver`) for web pages. Login and logout give the session a new id.
- `Auth().attempt(credentials)` finds the user and checks the bcrypt hash.
- `Auth().login(user)` gives a token with no password check.
- Custom drivers, like an API key guard. `Auth().setUser(req, user)` sets the user from your own middleware.
- `AuthMiddleware` answers `401` when the user is not logged in. With `redirectTo`, it sends the user to that page instead.
- More than one guard, like `web` and `admin`, each with its own driver and user model.
- The user is loaded from the database on each request with `dox_orm`.
- Gates and policies for authorization, with the `Can` middleware and `req.can`.

Things to know: a token expires after 1 hour by default. Change it with `expiresIn`.
By default a token holds the user (`toJson()`, hidden fields left out), like in 3.0.2. Anyone can read a token. The safer choice is `JwtAuthDriver(minimalPayload: true)`: the token then holds only the user id (the `sub` claim). Load the user with `req.auth?.user<User>()`, not from the token.
A session login ends with `Auth().logout(req)`.

### Revoke tokens

Each token has a random id (the `jti` claim). The JWT driver keeps revoked tokens in the app cache (`Cache()` of `dox_core`), so a revoked token stops working at once:

```dart
await Auth().logout(req);          // revoke the bearer token of this request
await Auth().revokeAllTokens(id);  // revoke all tokens of a user, eg. after a password change or a ban
await Auth().forgetUser(id);       // drop the user from `userCacheTtl`, eg. after a ban
```

- A revoked token stays on the deny-list only until it expires.
- `revokeAllTokens` keeps tokens made after the call. A token made in the same second as the call also still works.
- Give auth its own store, and never flush it. Pick it with `JwtAuthDriver(revocationStore: 'auth')`, for example a `redis` store with its own prefix. A flush of this store (`Cache().flush()`), or a `memory` store with `max_size` that drops old keys, brings revoked tokens back until they expire. With no `revocationStore`, the default app store is used.
- Cost: `verifyToken` reads this store on every request, also with `userCacheTtl`. It is one `many()` call: one round trip on `redis` and `memory`. On the `file` store (the default) it is 2 or 3 file reads per request. Use `memory` for one isolate, or `redis` for many isolates or servers. A `memory` store is seen by one isolate only.
- When the store can not be read, the token is checked like before (signature and `exp`), and a warning is printed once. A cache outage does not log everyone out, but revoked tokens work until the store is back.
- Tokens made before 3.0.3 have no `jti`. They still work until they expire, so an upgrade logs no one out. Logout can not put them on the deny-list. `revokeAllTokens` stops them when they have an `iat` claim (tokens from `JwtAuthDriver` do).
- The `revokeAllTokens` time comes from the server clock. Keep server clocks in sync (NTP). If the server that made a token has a clock that is ahead, its old tokens can pass the check.
With the default `cookie` session driver, all session data sits in the cookie. So an old copy of the cookie still works after logout. If logout must really end old cookies, use the `cache` session driver, like `SessionConfig(driver: 'cache', store: 'redis')`.

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
