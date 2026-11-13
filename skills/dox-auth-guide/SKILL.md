---
name: dox-auth-guide
description: Use when you add login or logout, JWT or session or access token guards, AuthMiddleware or GuestMiddleware, token revocation, a login throttle, or authorization with gates, policies and the Can middleware in a Dox (Dart) app.
---

# Dox auth

`dox_auth` checks an email and password, then gives a JWT or an access token (for an API), or keeps the login in the session (for web pages).
It also has gates and policies to say what a user may do.
For routes, controllers, DTOs and providers basics, see the `dox-core-guide` skill.
Long access token details are in `references/access-tokens.md`.

## Set up

An app with the ORM and a `User` model (`lib/app/models/user/user.model.dart`) sets up access token auth with one command:

```bash
dox add auth
dox migrate
```

It writes `lib/config/auth.dart` (an `api` guard), `lib/providers/auth_provider.dart` and the access tokens migration. It never overwrites a file. Without the ORM it stops and tells you to run `dox add orm` first.

## Setup

A new app does not have it. Add it:

```bash
dart pub add dox_auth
```

Set it up in a provider. Dox finds providers by itself. Run `dart run build_runner build` after you add one.

```dart
// lib/providers/auth_provider.dart
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:my_app/app/models/user/user.model.dart';
import 'package:my_app/config/env.dart';

class AppAuthProvider extends DoxProvider {
  @override
  void setup() {
    Auth.initialize(
      AuthConfig(
        defaultGuard: 'web',
        guards: <String, AuthGuard>{
          'web': AuthGuard(
            driver: JwtAuthDriver(
              secret: SecretKey(env.appKey),
              expiresIn: const Duration(days: 7),
            ),
            provider: AuthProvider(model: () => User()),
          ),
        },
      ),
    );
  }
}
```

- The user model must hide the password: `List<String> get hidden => <String>['password'];`.
- Passwords are checked with bcrypt. Store `Hash.make(...)` results (see `dox-core-guide`).
- Drivers: `JwtAuthDriver`, `SessionAuthDriver`, `AccessTokenAuthDriver`, or your own `AuthDriver`.
- `setup()` runs in every isolate. Gates and policies must be registered there too.

## Recipes

### 1. JWT login (API)

```dart
@Inject()
class AuthController {
  Future<dynamic> login(LoginUser body) async {
    Auth auth = Auth();
    String? token = await auth.attempt(<String, dynamic>{
      'email': body.email,
      'password': body.password,
    });
    if (token == null) {
      throw UnAuthorizedException(message: 'Wrong email or password');
    }
    return <String, dynamic>{'token': token, 'user': auth.user<User>()};
  }

  User? user(DoxRequest req) => req.auth?.user<User>();
}
```

```dart
Route.post('/auth/login', (AuthController c) => c.login);
Route.get('/auth/user', <dynamic>[AuthMiddleware(), (AuthController c) => c.user]);
```

The client sends `Authorization: Bearer <token>`.
`LoginUser` is a `@Dto` class with `email` and `password` (see `dox-validation-guide`).

Other `Auth` methods:

- `id()`: the user id, or null. `guest()`, `check()` and `isLoggedIn()`.
- `login(user)`: a token with no password check.
- `once(credentials)`: true or false. No token, no session.
- `Auth(guard: 'api')`: use another guard.

### 2. Session login (web pages)

Use `SessionAuthDriver()` as the driver. Add `SessionMiddleware()` and `CsrfMiddleware()` to `globalMiddleware`.

```dart
Future<dynamic> login(DoxRequest req, LoginUser body) async {
  bool ok = await Auth().attemptSession(req, <String, dynamic>{
    'email': body.email,
    'password': body.password,
  });
  if (!ok) {
    req.session.flashErrors(<String, dynamic>{'email': 'Wrong email or password'});
    return back(req);
  }
  return redirect('/dashboard');
}

DoxResponse logout(DoxRequest req) {
  Auth().logout(req);
  return redirect('/');
}
```

```dart
Route.get('/dashboard', <dynamic>[AuthMiddleware(redirectTo: '/login'), (PageController c) => c.dashboard]);
Route.get('/login', <dynamic>[GuestMiddleware(redirectTo: '/dashboard'), (PageController c) => c.login]);
```

- Login and logout give the session a new id.
- `Auth().logout(req)` is for the session guard only. On a JWT guard it throws.
- With the default `cookie` session driver, an old copy of the cookie still works after logout.
  To really end it, use the `cache` session driver: `SessionConfig(driver: 'cache', store: 'redis')`.

### 3. Middleware

- `AuthMiddleware()`: answers `401` for a guest. With `redirectTo`, it redirects instead.
- `AuthMiddleware(optional: true)`: guests go through. `req.auth` is null for a guest. `redirectTo` is not used.
- `AuthMiddleware(guard: 'api')` or `guards: <String>['web', 'api']`: tries each guard in order.
- `GuestMiddleware(redirectTo: '/dashboard')`: only guests. A logged-in user is redirected, or gets `403` with no `redirectTo`.
- After `AuthMiddleware`, `req.auth?.user<User>()` is the user and `req.auth?.id()` is the id.

### 4. Revoke JWTs (opt-in)

By default there is no server list of tokens. A JWT expires after 1 hour unless you set `expiresIn`.
Turn on revocation in the driver:

```dart
JwtAuthDriver(secret: SecretKey(env.appKey), revocation: true, revocationStore: 'auth')
```

```dart
await Auth().revokeToken(req);     // JWT logout
await Auth().revokeAllTokens(id);  // after a password change or a ban
await Auth().forgetUser(id);       // drop the user from userCacheTtl
```

- With revocation off, these three throw `StateError`.
- Give auth its own cache store and never flush it. Use `redis` for many isolates or servers.
- `JwtAuthDriver(minimalPayload: true)` puts only the user id in the token. The default token holds the user JSON, and anyone can read it.
- After an `APP_KEY` change, put the old key in `AppConfig.previousKeys` so old tokens still work until they expire.

### 5. Access tokens (revocable API tokens)

Opaque tokens in a database table, with abilities.

```dart
'api': AuthGuard(
  driver: AccessTokenAuthDriver(),
  provider: AuthProvider(model: () => User()),
),
```

```bash
dox auth:tokens-table --users-table=users
dox migration:run
```

```dart
AccessToken token = await Auth(guard: 'api').createAccessToken(
  user,
  name: 'cli',
  abilities: <String>['posts:read'],
  expiresIn: const Duration(days: 30),
);
return <String, dynamic>{'token': token.value}; // shown once

Auth auth = req.auth as Auth;
if (!auth.tokenCan('posts:write')) throw ForbiddenHttpException();
```

Protect routes with `AuthMiddleware(guard: 'api')`.
See `references/access-tokens.md` for revoke, rotate, the migration options and errors.

### 6. Throttle logins

Off by default. Turn on in a provider `setup()`:

```dart
Auth.throttle = LoginThrottle(maxAttempts: 5, decay: const Duration(minutes: 1));

String? token = await Auth(ip: req.ip()).attempt(credentials); // JWT: pass the ip
bool ok = await Auth().attemptSession(req, credentials);       // session: ip is read for you
```

- Too many fails throw `LoginThrottledException` (429). `retryAfter` says how long to wait.
- Use `LoginThrottle(store: 'redis')` for many isolates or servers.
- Parallel guesses can pass the check. Also put `RateLimit` on the login route.

### 7. Custom guard (API key)

```dart
class ApiKeyAuthDriver extends AuthDriver {
  @override
  Future<Model<dynamic>?> verifyToken(IDoxRequest req, String guard) async {
    String header = req.header('Authorization') ?? '';
    if (!header.startsWith('Bearer ')) return null;
    Model<dynamic> model = AuthEngine().guard(guard).provider.model();
    return await model.where('api_key', header.substring(7).trim()).getFirst();
  }

  @override
  Future<Model<dynamic>?> attempt(Map<String, dynamic> credentials, String guard) async => null;

  @override
  String? createToken(Map<String, dynamic>? userPayload, String guard) => null;
}
```

Add it as a guard (`AuthGuard(driver: ApiKeyAuthDriver(), provider: ...)`) and use `AuthMiddleware(guard: 'api')`.
Store a hash of the key, not the key. From your own middleware you can call `Auth(guard: 'api').setUser(req, user)`.

### 8. Login with no request (Socket.IO)

```dart
User? user = await Auth(guard: 'api').userFromToken(token);        // no "Bearer " prefix
User? user = await Auth(guard: 'web').userFromSession(session);
```

A bad, expired or revoked token gives `null`.

### 9. Gates and policies

```dart
Gate.define('update-post', (User user, Post post) => post.userId == user.id);

await Gate.allows(user, 'update-post', post);    // true or false
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
await Gate.allows(user, 'create', Post); // no model: pass the type
```

In a controller: `await req.authorize('update', post);`, `req.can(...)`, `req.cannot(...)`.
On a route, put `Can` after `AuthMiddleware`:

```dart
Route.post('/posts', <dynamic>[AuthMiddleware(), Can('create', subject: Post), (PostController c) => c.store]);
Route.put('/posts/{post}', <dynamic>[AuthMiddleware(), Can('update', param: 'post'), (PostController c) => c.update]);
```

- A guest gets `401`. A user who may not do it gets `403`.
- `param` uses the value of `Route.bind` for that route param.
- A check may return `GateResponse.deny('Why')` to set the 403 message.
- `Gate.before((User user, String ability) => user.isAdmin ? true : null)` decides first. Also `Gate.after`, `Gate.any`, `Gate.all`.
- A guest is denied, unless the user type is nullable: `(User? user, Post post)`.
- Register gates and policies in a `DoxProvider` `setup()`. They are kept per isolate.

### 10. Auth flags (opt-in behavior)

```dart
AuthConfig(defaultGuard: 'web', guards: guards, flags: const AuthFlags(forbidGuest: true, jsonNoRedirect: true));
```

- `forbidGuest`: a guest gets `403`, not `401`, from `req.authorize()` and `Can`.
- `jsonNoRedirect`: JSON and XHR clients get `401`, not a redirect, from `AuthMiddleware(redirectTo: ...)`.
- `AuthFlags.all()` turns on every flag.

## Gotchas

- `Auth.initialize` must run in every isolate. Do it in a provider `setup()`, not in `main()`.
- `attempt` and `attemptSession` are async. Always `await` them.
- `attempt` gives `null` on wrong credentials. It does not throw. Throw `UnAuthorizedException` yourself.
- `Auth().login(user)` throws `StateError` with `AccessTokenAuthDriver`. Use `createAccessToken`.
- `Auth.throttle` is static. Set it per isolate.
- Higher bcrypt cost: set `Hash.rounds = 12` and pass `hashRounds: 12` to the driver. Then use `Auth.needsRehash(user.password)` on login.
