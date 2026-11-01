// ignore_for_file: depend_on_referenced_packages
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_orm/dox_orm.dart';

class JwtAuthDriver extends AuthDriver {
  /// Jwt secret.
  /// A [SecretKey] (like `SecretKey(env.appKey)`) is not used as it is.
  /// The HMAC key is made from it with HKDF-SHA256 and the label
  /// `dox:jwt` (see `KeyDerivation`), so APP_KEY is not shared with
  /// cookies or other uses. [signingKey] gives that key, for another
  /// service that checks the tokens. Other keys (RSA, EC) are used as
  /// they are.
  final JWTKey secret;

  /// The key that signs and checks the tokens. See [secret].
  late final JWTKey signingKey = _signingKey(secret);

  /// Old secrets, used only to check tokens after a key change.
  /// New tokens are always signed with [secret].
  /// When this is `null` and [secret] is the APP_KEY of the app, the
  /// old keys come from `AppConfig.previousKeys`. Pass `[]` to turn
  /// this off.
  final List<JWTKey>? previousSecrets;

  /// The keys that check tokens made with an old secret. Made on first
  /// use, because `Dox().config` may be set after this driver.
  late final List<JWTKey> previousSigningKeys = <JWTKey>[
    for (JWTKey old in previousSecrets ?? _previousAppKeys()) _signingKey(old),
  ];

  /// old APP_KEYs, only when [secret] is the current APP_KEY
  List<JWTKey> _previousAppKeys() {
    JWTKey key = secret;
    if (key is! SecretKey) return <JWTKey>[];
    AppConfig config;
    try {
      config = Dox().config;
    } on Error {
      /// Dox is not initialized, so there are no old keys
      return <JWTKey>[];
    }
    if (key.key != config.appKey) return <JWTKey>[];
    return <JWTKey>[for (String old in config.previousKeys) SecretKey(old)];
  }

  /// JWT issuer
  final String? issuer;

  /// JWT algorithm
  final JWTAlgorithm algorithm;

  /// How long a token is valid. Default: 1 hour.
  final Duration expiresIn;

  /// bcrypt cost of the stored password hashes. Default: 10.
  /// Set it to the cost you use with `Hash.make`, so a login for an
  /// unknown email takes as long as a wrong password.
  final int hashRounds;

  /// Keep the user of a token in memory for this long, so
  /// `verifyToken` does not load the user from the database on every
  /// request. Off (`null`) by default.
  /// A change to the user (eg. delete or ban) is seen only after this
  /// time, unless you call `Auth().forgetUser(id)` (needs [revocation]). Each server isolate
  /// has its own cache. Requests in this time share the same user
  /// object, so do not change it per request.
  final Duration? userCacheTtl;

  /// Turn on token revocation: `Auth().revokeToken(req)`,
  /// `Auth().revokeAllTokens(id)` and `Auth().forgetUser(id)`. Off by
  /// default, so `verifyToken` never reads the cache, like in 3.0.2.
  ///
  /// When on, `verifyToken` reads [revocationStore] on every request.
  /// When off, the revoke methods throw a [StateError], so no one thinks
  /// a token is revoked when it is not.
  final bool revocation;

  /// The name of the store in `AppConfig.cache` that keeps revoked
  /// tokens, the `revokeAllTokens` times and the `forgetUser` times.
  /// null is the default store of the app.
  ///
  /// Give auth its own store and never flush it. A flush of this store,
  /// or a `memory` store with `max_size` that drops old keys, brings
  /// revoked tokens back until they expire.
  ///
  /// `verifyToken` reads this store on each request with one `many()`
  /// call: one round trip on `redis` and `memory`, but one file read per
  /// key (2 or 3) on the `file` store. Use `memory` for one isolate, or
  /// a shared store like `redis` for many isolates or servers.
  final String? revocationStore;

  /// most users kept by [userCacheTtl]. When full, the cache is cleared.
  static const int _userCacheSize = 1000;

  /// the user, when the entry expires, and when it was loaded (ms)
  final Map<String, (Model<dynamic>, DateTime, int)> _userCache =
      <String, (Model<dynamic>, DateTime, int)>{};

  static final Random _random = Random.secure();

  bool _warnedStoreDown = false;

  /// Put only the user id (the `sub` claim) in new tokens, not the user
  /// columns. Off by default, so tokens look like in 3.0.2: the user
  /// (`toJson()`, hidden fields left out) plus `jti`, `iat` and `exp`.
  ///
  /// Turn it on when you can: anyone can read a JWT payload, and a
  /// small token is cheaper to send. A front end that reads user fields
  /// from the token must then load the user from the API.
  final bool minimalPayload;

  /// constructor
  JwtAuthDriver({
    required this.secret,
    this.algorithm = JWTAlgorithm.HS256,
    this.expiresIn = const Duration(hours: 1),
    this.issuer,
    this.hashRounds = 10,
    this.userCacheTtl,
    this.previousSecrets,
    this.revocationStore,
    this.minimalPayload = false,
    this.revocation = false,
  }) {
    /// with an empty key anyone can sign a token for any user
    JWTKey key = secret;
    if (key is SecretKey && key.key.trim().isEmpty) {
      throw ArgumentError(
        'The JWT secret is empty. Set APP_KEY (run `dox key:generate`).',
        'secret',
      );
    }
    if (key is SecretKey) _checkSecretLength(key.key);

    AuthDriver.prepareDummyHash(hashRounds);
  }

  static JWTKey _signingKey(JWTKey secret) {
    if (secret is! SecretKey) return secret;
    return SecretKey(
      base64.encode(KeyDerivation.derive(secret.key, KeyDerivation.jwt)),
      isBase64Encoded: true,
    );
  }

  /// fewest bytes of an HMAC secret. A shorter one is easy to guess.
  static const int minSecretBytes = 32;

  /// A short secret stops the app in production, and only warns in
  /// development, local, test and testing (like the APP_KEY check of
  /// dox_core).
  static void _checkSecretLength(String secret) {
    int length = utf8.encode(secret).length;
    if (length >= minSecretBytes) return;
    String message =
        'The JWT secret is $length bytes. It must be at least '
        '$minSecretBytes bytes. Run `dox key:generate` for APP_KEY, '
        'or make a secret with `openssl rand -hex 32`.';
    String env = Env.get<String>('APP_ENV').toLowerCase();
    if (!<String>['development', 'local', 'test', 'testing'].contains(env)) {
      throw ArgumentError(message, 'secret');
    }
    print('[dox] warning: $message');
  }

  static final RegExp _bearerPrefix = RegExp(r'^bearer ', caseSensitive: false);

  /// The token in the `Authorization` header of [req], or null.
  /// The `Bearer ` prefix is matched in any case (`bearer`, `BEARER`).
  /// A header with no prefix is used as it is, like in 3.0.2.
  static String? bearerToken(IDoxRequest req) {
    return req.header('Authorization')?.replaceFirst(_bearerPrefix, '');
  }

  /// verify token and get model from provider
  /// and get user data
  @override
  Future<Model<dynamic>?> verifyToken(IDoxRequest req, String guard) async {
    try {
      AuthProvider provider = AuthEngine().guard(guard).provider;

      /// get token from header
      String? token = bearerToken(req);

      /// if not token just return
      if (token == null) {
        return null;
      }

      Map<String, dynamic> payload = _payload(token, guard);

      /// get model from provider
      Model<dynamic> model = provider.model();

      /// The user id. A full token (3.0.2, and the default now) holds the
      /// user, so the id is under the primary key, like in 3.0.2. A
      /// user column named `sub` is never read. Only a small token
      /// ([minimalPayload]: a `jti`, no user columns) keeps it in `sub`.
      dynamic jti = payload['jti'];
      dynamic id = payload.containsKey(model.primaryKey)
          ? payload[model.primaryKey]
          : (jti is String ? payload['sub'] : null);
      if (id == null) {
        return null;
      }

      /// A token made before 3.0.3 has no `jti`. It still works until it
      /// expires, so an upgrade logs no one out. It can not be put on
      /// the deny-list, but `revokeAllTokens` still stops it by its `iat`.
      dynamic iat = payload['iat'];

      /// one cache read for all checks. With [revocation] off there is
      /// no cache read at all, like in 3.0.2.
      String userKey = '$guard:$id';
      Duration? ttl = userCacheTtl;
      Map<String, dynamic> found = !revocation
          ? const <String, dynamic>{}
          : await _readRevocations(<String>[
              if (jti is String) _revokedKey(jti),
              _validAfterKey(userKey),
              if (ttl != null) _freshAfterKey(userKey),
            ]);

      /// logged out
      if (jti is String && found[_revokedKey(jti)] != null) {
        return null;
      }

      /// made before `revokeAllTokens`
      dynamic validAfter = found[_validAfterKey(userKey)];
      if (validAfter is num && iat is num && iat < validAfter) {
        return null;
      }

      if (ttl == null) {
        /// by user by id
        return await model.find(id);
      }

      DateTime now = DateTime.now();
      (Model<dynamic>, DateTime, int)? cached = _userCache[userKey];
      dynamic freshAfter = found[_freshAfterKey(userKey)];
      bool forgotten =
          freshAfter is num && cached != null && cached.$3 <= freshAfter;
      if (cached != null && now.isBefore(cached.$2) && !forgotten) {
        return cached.$1;
      }
      Model<dynamic>? user = await model.find(id);
      if (user == null) {
        _userCache.remove(userKey);
        return null;
      }
      if (_userCache.length >= _userCacheSize) {
        _userCache.clear();
      }
      _userCache[userKey] = (user, now.add(ttl), now.millisecondsSinceEpoch);
      return user;
    } catch (ex) {
      /// ignore any errors
    }
    return null;
  }

  /// The checked payload of [token]. Throws when the token is bad.
  Map<String, dynamic> _payload(String token, String guard) {
    /// only the configured algorithm is accepted, so a token can not
    /// pick another one (like `none`, or HS256 with a public RSA key).
    if (JWT.decode(token).header?['alg'] != algorithm.name) {
      throw JWTInvalidException('invalid algorithm');
    }

    /// the audience is the guard name, so a token of one guard
    /// does not work for another guard.
    return _verify(token, guard).payload as Map<String, dynamic>;
  }

  CacheStore get _cache => Dox().cache.store(revocationStore);

  /// Reads [keys] from [revocationStore]. When the store can not be
  /// read, the token is checked like in 3.0.2 (signature and `exp`
  /// only), with a warning, so a cache outage does not log everyone out.
  Future<Map<String, dynamic>> _readRevocations(List<String> keys) async {
    try {
      return await _cache.many(keys);
    } catch (error) {
      // ponytail: warns once per driver (per isolate), so a long outage does not
      // flood the log. Later outages are silent.
      if (_warnedStoreDown) return <String, dynamic>{};
      _warnedStoreDown = true;
      print(
        '[dox] warning: dox_auth can not read the revocation store '
        '($error). Revoked tokens are accepted until it works again.',
      );
      return <String, dynamic>{};
    }
  }

  static String _revokedKey(String jti) => 'auth:revoked:$jti';

  static String _validAfterKey(String userKey) => 'auth:valid_after:$userKey';

  static String _freshAfterKey(String userKey) => 'auth:fresh_after:$userKey';

  /// A random token id (`jti`), so one token can be revoked.
  static String _newJti() {
    Uint8List bytes = Uint8List(16);
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  /// Seconds since epoch, like the `iat` and `exp` claims.
  static int _nowSeconds() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

  /// Throws when [revocation] is off.
  void _needRevocation(String method) {
    if (revocation) return;
    throw StateError(
      '$method needs token revocation. '
      'Turn it on with JwtAuthDriver(revocation: true).',
    );
  }

  /// Revoke [token] (eg. on logout). Its `jti` goes on a deny-list in
  /// the cache until the token expires. A bad or expired token, or one
  /// with no `jti` (made before 3.0.3), is ignored. Needs [revocation].
  Future<void> revokeToken(String? token, String guard) async {
    _needRevocation('revokeToken');
    if (token == null) return;
    Map<String, dynamic> payload;
    try {
      payload = _payload(token, guard);
    } on JWTException {
      return;
    }
    dynamic jti = payload['jti'];
    dynamic exp = payload['exp'];
    if (jti is! String) return;
    Duration life = exp is num
        ? Duration(seconds: exp.toInt() - _nowSeconds() + 1)
        : expiresIn;
    await _cache.put(_revokedKey(jti), 1, life);
  }

  /// Revoke all tokens of the user [id] made before now (eg. after a
  /// password change or a ban). Tokens made after this call work.
  /// Also drops the user from [userCacheTtl]. Needs [revocation].
  Future<void> revokeAllTokens(dynamic id, String guard) async {
    _needRevocation('revokeAllTokens');

    /// ponytail: iat is in whole seconds, so a token made in the same
    /// second as this call still works. A ms claim would close it.
    /// kept as long as a new token lives; older tokens expired by then.
    await _cache.put(
      _validAfterKey('$guard:$id'),
      _nowSeconds(),
      expiresIn + Duration(seconds: 1),
    );
    await forgetUser(id, guard);
  }

  /// Drop the user [id] from [userCacheTtl] on all isolates and
  /// servers that share [revocationStore], so the next request loads it
  /// from the database (eg. after a ban or a delete). Needs [revocation].
  Future<void> forgetUser(dynamic id, String guard) async {
    _needRevocation('forgetUser');
    String userKey = '$guard:$id';
    _userCache.remove(userKey);
    Duration? ttl = userCacheTtl;
    if (ttl == null) return;
    await _cache.put(
      _freshAfterKey(userKey),
      DateTime.now().millisecondsSinceEpoch,
      ttl,
    );
  }

  /// the current key first, then the old keys. made once.
  late final List<JWTKey> _verifyKeys = <JWTKey>[
    signingKey,
    ...previousSigningKeys,
  ];

  /// Checks [token] with the current key, then with each old key.
  /// Only a wrong signature moves to the next key. An expired token or
  /// a bad claim fails at once.
  JWT _verify(String token, String guard) {
    List<JWTKey> keys = _verifyKeys;
    for (int i = 0; ; i++) {
      try {
        return JWT.verify(
          token,
          keys[i],
          audience: Audience.one(guard),
          issuer: issuer,
        );
      } on JWTInvalidException catch (e) {
        bool badSignature = e.message == 'invalid signature';
        if (!badSignature || i == keys.length - 1) rethrow;
      }
    }
  }

  /// attempt to login
  ///```
  /// String token = await auth.attempt(credentials);
  /// if(token == null) {
  ///   // failed to login
  /// }
  ///```
  @override
  Future<Model<dynamic>?> attempt(
    Map<String, dynamic> credentials,
    String guard,
  ) {
    return AuthDriver.checkCredentials(credentials, guard, hashRounds);
  }

  /// set login and get jwt token
  /// ```
  /// String token = auth.login(user);
  /// ```
  /// By default the token holds [userPayload], like in 3.0.2, plus a
  /// `jti`. With [minimalPayload], it holds only the user id as `sub`:
  /// the primary key of [userPayload], or its `sub` when the primary
  /// key is missing.
  @override
  String? createToken(Map<String, dynamic>? userPayload, String guard) {
    try {
      Map<String, dynamic> payload = <String, dynamic>{...?userPayload};
      if (minimalPayload) {
        String key = AuthEngine().guard(guard).provider.model().primaryKey;
        dynamic id = payload[key] ?? payload['sub'];
        if (id == null) return null;
        payload = <String, dynamic>{'sub': id};
      }
      JWT jwt = JWT(
        payload,
        issuer: issuer,
        audience: Audience.one(guard),
        jwtId: _newJti(),
      );
      return jwt.sign(signingKey, algorithm: algorithm, expiresIn: expiresIn);
    } catch (error) {
      return null;
    }
  }
}
