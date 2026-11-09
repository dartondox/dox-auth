// ignore_for_file: depend_on_referenced_packages
import 'dart:io';

import 'package:dox_auth/src/auth_engine.dart';
import 'package:dox_auth/src/drivers/access_token_auth_driver.dart';
import 'package:dox_auth/src/drivers/jwt_auth_driver.dart';
import 'package:dox_auth/src/drivers/session_auth_driver.dart';
import 'package:dox_auth/src/interfaces.dart';
import 'package:dox_auth/src/login_throttle.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_orm/dox_orm.dart';

class Auth implements IAuth {
  /// The guard name from `AuthConfig.guards`.
  /// null uses `AuthConfig.defaultGuard`.
  /// ```
  /// Auth(guard: 'admin').attempt(credentials);
  /// ```
  final String? guard;

  /// The client ip, for [throttle]. Only `attempt` uses it;
  /// `attemptSession` reads it from the request.
  /// ```
  /// Auth(ip: req.ip()).attempt(credentials);
  /// ```
  final String? ip;

  Auth({this.guard, this.ip});

  /// user data
  Model<dynamic>? _userData;

  String get _guard => guard ?? AuthEngine().config.defaultGuard;

  AuthDriver get _driver => AuthEngine().guard(_guard).driver;

  static final RegExp _bcryptCost = RegExp(r'^\$2[abxy]?\$(\d{2})\$');

  /// The bcrypt cost of [hash], or null when it is not a bcrypt hash.
  /// ```
  /// Auth.hashCost(r'$2a$10$...'); // 10
  /// ```
  static int? hashCost(String hash) {
    String? cost = _bcryptCost.firstMatch(hash)?.group(1);
    return cost == null ? null : int.parse(cost);
  }

  /// true when [hash] was not made with the cost [rounds] (default:
  /// `Hash.rounds`), or is not a bcrypt hash. After you raise the cost,
  /// hash the password again on the next good login:
  /// ```
  /// if (Auth.needsRehash(user.password)) {
  ///   user.password = Hash.make(password);
  ///   await user.save();
  /// }
  /// ```
  static bool needsRehash(String hash, {int? rounds}) {
    return hashCost(hash) != (rounds ?? Hash.rounds);
  }

  static void initialize(AuthConfig authConfig) {
    AuthEngine().init(authConfig);
  }

  /// The access token of this request, with `AccessTokenAuthDriver`.
  /// null with other drivers, or when there is no login.
  AccessToken? get currentAccessToken => _accessToken;

  AccessToken? _accessToken;

  /// the token that [verifyToken] found for the request, for
  /// [revokeToken]. [userFromToken] does not set it.
  AccessToken? _requestToken;

  @override
  Future<void> verifyToken(IDoxRequest req) async {
    AuthDriver driver = _driver;
    _userData = await driver.verifyToken(req, _guard);
    if (driver is AccessTokenAuthDriver) {
      AccessToken? token = AccessTokenAuthDriver.tokenOf(req);
      Model<dynamic>? user = _userData;
      _accessToken = _requestToken =
          user != null && identical(token?.user, user) ? token : null;
    }
  }

  /// true when the access token of this request has [ability] (or `*`).
  /// false when there is no access token, so a session or JWT login
  /// never passes this check.
  /// ```
  /// if (!(req.auth as Auth).tokenCan('posts:write')) {
  ///   throw ForbiddenHttpException();
  /// }
  /// ```
  bool tokenCan(String ability) => _accessToken?.can(ability) ?? false;

  /// A new access token for [user]. Show `token.value` to the user
  /// once: only its hash is kept. [abilities] default to `['*']` (all).
  /// [expiresIn] default to `AccessTokenAuthDriver.expiresIn`.
  /// Needs `AccessTokenAuthDriver`.
  /// ```
  /// AccessToken token = await Auth(guard: 'api').createAccessToken(
  ///   user,
  ///   name: 'cli',
  ///   abilities: ['posts:read'],
  ///   expiresIn: Duration(days: 30),
  /// );
  /// return {'token': token.value};
  /// ```
  Future<AccessToken> createAccessToken(
    Model<dynamic> user, {
    String? name,
    List<String> abilities = const <String>['*'],
    Duration? expiresIn,
  }) {
    return _accessTokenDriver.create(
      user,
      _guard,
      name: name,
      abilities: abilities,
      expiresIn: expiresIn,
    );
  }

  /// All access tokens of [user], newest first. Needs `AccessTokenAuthDriver`.
  Future<List<AccessToken>> accessTokens(Model<dynamic> user) {
    return _accessTokenDriver.all(user, _guard);
  }

  /// Revoke (delete) the access token [id] of [user]. false when [user]
  /// has no token with this id. Needs `AccessTokenAuthDriver`.
  Future<bool> revokeAccessToken(Model<dynamic> user, int id) {
    return _accessTokenDriver.revoke(user, _guard, id);
  }

  /// Delete the expired access tokens of the table of this guard.
  /// Gives how many were deleted. Run it from a scheduled job.
  /// Needs `AccessTokenAuthDriver`.
  Future<int> pruneExpiredAccessTokens() {
    return _accessTokenDriver.pruneExpired();
  }

  /// Revoke (delete) all access tokens of [user], eg. after a password
  /// change. Gives how many were deleted. Needs `AccessTokenAuthDriver`.
  Future<int> revokeAllAccessTokens(Model<dynamic> user) {
    return _accessTokenDriver.revokeAll(user, _guard);
  }

  /// The user of [token] (a JWT or an access token), or null. For code
  /// with no request, like a socket. Same checks as a request with a
  /// `Bearer` header: a null, bad, expired, revoked or changed token
  /// gives null. Needs a guard with `JwtAuthDriver` or
  /// `AccessTokenAuthDriver`. With an access token, [currentAccessToken]
  /// and [tokenCan] work after it.
  /// ```
  /// User? user = await Auth(guard: 'api').userFromToken(handshake.token);
  /// ```
  Future<T?> userFromToken<T>(String? token) async {
    AuthDriver driver = _driver;
    if (driver is AccessTokenAuthDriver) {
      _accessToken = token == null ? null : await driver.check(token, _guard);
      _userData = _accessToken?.user;
      return _userData as T?;
    }
    _userData = await _jwtDriver.userFromToken(token, _guard);
    return _userData as T?;
  }

  /// The user that is logged in to [session], or null. For code with no
  /// request, like a socket. Needs a guard with `SessionAuthDriver`.
  /// ```
  /// User? user = await Auth(guard: 'web').userFromSession(session);
  /// ```
  Future<T?> userFromSession<T>(Session session) async {
    _userData = await _sessionDriver.userFromSession(session, _guard);
    return _userData as T?;
  }

  @override
  bool isLoggedIn() {
    return _userData != null;
  }

  /// The same as [isLoggedIn], with the Laravel name.
  bool check() => isLoggedIn();

  @override
  T? user<T>() {
    return _userData as T?;
  }

  /// true when nobody is logged in. The opposite of [isLoggedIn].
  bool guest() => !isLoggedIn();

  /// The primary key of the logged-in user, or null for a guest. It is
  /// read even when the key is hidden from `toJson()`.
  /// ```
  /// if (post.userId != req.auth?.id()) abort(403);
  /// ```
  dynamic id() {
    Model<dynamic>? user = _userData;
    return user?.toMap(original: true)[user.primaryKey];
  }

  /// The login throttle for `attempt` and `attemptSession`.
  /// Off (`null`) by default, like in 3.0.2. See [LoginThrottle].
  /// ```
  /// Auth.throttle = LoginThrottle(maxAttempts: 5, decay: Duration(minutes: 1));
  /// ```
  static LoginThrottle? throttle;

  /// Check the credentials and give a token, or null when they are wrong.
  /// With [throttle] on, make the `Auth` with the client [ip]
  /// (`Auth(ip: req.ip())`), so the count is per account and ip.
  /// Without an ip, the count is per account only, so anyone can lock
  /// an account for `decay`.
  /// With `AccessTokenAuthDriver`, it gives a new access token with all
  /// abilities (see [createAccessToken]).
  Future<String?> attempt(Map<String, dynamic> credentials) async {
    _accessToken = null;
    _userData = await _throttled(credentials, ip);
    Model<dynamic>? user = _userData;
    if (user != null && _driver is AccessTokenAuthDriver) {
      return (await createAccessToken(user)).value;
    }
    return _createToken();
  }

  /// Check the credentials and log the user in for this `Auth` only.
  /// true when they are right. Like Laravel `Auth::once`: it makes no
  /// token and does not touch the session, so it works on any guard.
  /// [throttle] counts it like [attempt]. Use [attempt] for a token, or
  /// [attemptSession] to keep the login in the session.
  /// ```
  /// Auth auth = Auth(ip: req.ip());
  /// if (!await auth.once(credentials)) throw UnAuthorizedException();
  /// User user = auth.user<User>()!;
  /// ```
  Future<bool> once(Map<String, dynamic> credentials) async {
    _accessToken = null;
    _userData = await _throttled(credentials, ip);
    return _userData != null;
  }

  /// [AuthDriver.attempt], with [throttle] when it is on.
  Future<Model<dynamic>?> _throttled(
    Map<String, dynamic> credentials,
    String? ip,
  ) async {
    AuthDriver driver = _driver;
    LoginThrottle? limit = throttle;
    if (limit == null) return driver.attempt(credentials, _guard);

    List<String> fields = AuthEngine().guard(_guard).provider.identifierFields;
    String key = LoginThrottle.key(_guard, <Object?>[
      for (String field in fields) credentials[field],
    ], ip);
    await limit.check(key);
    Model<dynamic>? user = await driver.attempt(credentials, _guard);
    if (user == null) {
      await limit.hit(key);
    } else {
      await limit.clear(key);
    }
    return user;
  }

  String? login(Model<dynamic> user) {
    _userData = user;
    return _createToken();
  }

  /// Set [user] as the logged-in user of [req], with no token and no
  /// password check. For your own auth middleware, like an API key check.
  /// `req.auth` then gives this user.
  /// ```
  /// Auth(guard: 'api').setUser(req, user);
  /// req.auth?.user<User>();
  /// ```
  void setUser(IDoxRequest req, Model<dynamic> user) {
    _userData = user;
    req.auth = this;
  }

  /// Check the credentials and keep the login in the session.
  /// true when it worked. Needs a guard with `SessionAuthDriver`.
  /// ```
  /// if (!await Auth().attemptSession(req, credentials)) {
  ///   req.session.flashErrors({'email': 'Wrong email or password'});
  ///   return back(req);
  /// }
  /// ```
  Future<bool> attemptSession(
    DoxRequest req,
    Map<String, dynamic> credentials,
  ) async {
    SessionAuthDriver driver = _sessionDriver;
    try {
      _userData = await _throttled(credentials, req.ip());
    } on LoginThrottledException catch (error) {
      req.httpRequest.response.headers.set(
        HttpHeaders.retryAfterHeader,
        (error.retryAfter.inMilliseconds / 1000).ceil(),
      );
      rethrow;
    }
    Model<dynamic>? user = _userData;
    if (user == null) return false;
    driver.login(req, user, _guard);
    return true;
  }

  /// Keep [user] in the session, with no password check.
  /// Needs a guard with `SessionAuthDriver`.
  void loginSession(DoxRequest req, Model<dynamic> user) {
    _userData = user;
    _sessionDriver.login(req, user, _guard);
  }

  /// End the session login. All session data is removed.
  void logout(DoxRequest req) {
    _userData = null;
    _sessionDriver.logout(req);
  }

  /// Revoke the bearer token of [req] (a token logout).
  /// - `JwtAuthDriver` (needs `revocation: true`): the token is kept on
  ///   a deny-list in the cache until it expires.
  /// - `AccessTokenAuthDriver`: the token row is deleted. A token that
  ///   does not check out does nothing. On the `Auth` of `AuthMiddleware`
  ///   (`(req.auth as Auth).revokeToken(req)`) it uses the token that
  ///   was already checked, with no second check.
  ///
  /// A request with no token does nothing.
  /// ```
  /// await Auth().revokeToken(req);
  /// ```
  Future<void> revokeToken(IDoxRequest req) async {
    AuthDriver current = _driver;
    if (current is AccessTokenAuthDriver) {
      /// the token of `verifyToken` (eg. from `AuthMiddleware`), so it
      /// is not checked again. A token of `userFromToken` is not used: it
      /// is not the token of the request. Else the driver checks the
      /// request, with its own `verifyToken` (a bad header gives no
      /// token, not an error).
      AccessToken? found = _requestToken;
      if (found == null) {
        Model<dynamic>? user = await current.verifyToken(req, _guard);
        AccessToken? token = AccessTokenAuthDriver.tokenOf(req);
        if (user != null && identical(token?.user, user)) found = token;
      }
      Model<dynamic>? user = found?.user;
      if (found != null && user != null) {
        await current.revoke(user, _guard, found.id);
      }
      _userData = null;
      _accessToken = _requestToken = null;
      return;
    }
    JwtAuthDriver driver = _jwtDriver;
    _userData = null;
    String? token = JwtAuthDriver.bearerToken(req);
    await driver.revokeToken(token, _guard);
  }

  /// Revoke all tokens of the user [id] made before the current second
  /// (the `iat` claim is in whole seconds), on all servers that share
  /// the cache. Use it after a password change or a ban. Tokens made in
  /// the same second as this call, or later, still work. Needs
  /// `JwtAuthDriver` with `revocation: true`.
  /// ```
  /// await Auth().revokeAllTokens(user.id);
  /// ```
  Future<void> revokeAllTokens(dynamic id) {
    return _jwtDriver.revokeAllTokens(id, _guard);
  }

  /// Drop the user [id] from the `userCacheTtl` cache, so the next
  /// request loads it from the database. Use it after a ban or a
  /// change to the user. Needs `JwtAuthDriver` with `revocation: true`.
  /// ```
  /// await Auth().forgetUser(user.id);
  /// ```
  Future<void> forgetUser(dynamic id) {
    return _jwtDriver.forgetUser(id, _guard);
  }

  AccessTokenAuthDriver get _accessTokenDriver {
    AuthDriver driver = _driver;
    if (driver is AccessTokenAuthDriver) return driver;
    throw StateError(
      "The auth guard '$_guard' does not use AccessTokenAuthDriver.",
    );
  }

  JwtAuthDriver get _jwtDriver {
    AuthDriver driver = _driver;
    if (driver is JwtAuthDriver) return driver;
    throw StateError("The auth guard '$_guard' does not use JwtAuthDriver.");
  }

  SessionAuthDriver get _sessionDriver {
    AuthDriver driver = _driver;
    if (driver is SessionAuthDriver) return driver;
    throw StateError(
      "The auth guard '$_guard' does not use SessionAuthDriver. "
      'Use attempt() and login() for a token, and revokeToken() to log out.',
    );
  }

  @override
  Map<String, dynamic>? toJson() {
    return _userData?.toJson();
  }

  /// The driver gets `user.toJson()`, like in 3.0.2. When the primary
  /// key is hidden, the id is added as `sub`, so the driver still knows
  /// the user.
  String? _createToken() {
    Model<dynamic>? user = _userData;
    if (user == null) {
      return null;
    }
    Map<String, dynamic> data = user.toJson();
    if (!data.containsKey(user.primaryKey)) {
      data['sub'] = user.toMap(original: true)[user.primaryKey];
    }
    return _driver.createToken(data, _guard);
  }
}
