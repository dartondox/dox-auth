// ignore_for_file: depend_on_referenced_packages
import 'dart:io';

import 'package:dox_auth/src/auth_engine.dart';
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

  @override
  Future<void> verifyToken(IDoxRequest req) async {
    _userData = await _driver.verifyToken(req, _guard);
  }

  @override
  bool isLoggedIn() {
    return _userData != null;
  }

  @override
  T? user<T>() {
    return _userData as T?;
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
  Future<String?> attempt(Map<String, dynamic> credentials) async {
    _userData = await _throttled(credentials, ip);
    return _createToken();
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
    // fail early with the clear "no session" error, before the password
    // check, so a wrong password does not hide a missing SessionMiddleware
    req.session;
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

  /// Revoke the bearer token of [req] (a JWT logout). It is kept on a
  /// deny-list in the cache until it expires. Needs `JwtAuthDriver` with
  /// `revocation: true`. A request with no token does nothing.
  /// ```
  /// await Auth().revokeToken(req);
  /// ```
  Future<void> revokeToken(IDoxRequest req) async {
    JwtAuthDriver driver = _jwtDriver;
    _userData = null;
    String? token = JwtAuthDriver.bearerToken(req);
    await driver.revokeToken(token, _guard);
  }

  /// Revoke all tokens of the user [id] made before now, on all
  /// servers that share the cache. Use it after a password change or a
  /// ban. Tokens made after this call work. Needs `JwtAuthDriver` with
  /// `revocation: true`.
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
      'Use attempt() and login() for a token.',
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
