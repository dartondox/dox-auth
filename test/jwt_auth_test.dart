// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_orm/dox_orm.dart';
import 'package:test/test.dart';

const String secret = '4HyiSrq4N5Nfg6bOadIhbFEI8zbUkpxt';

/// the key that the driver signs with: made from [secret], see
/// `JwtAuthDriver.signingKey`
final JWTKey signingKey = JwtAuthDriver(secret: SecretKey(secret)).signingKey;

/// In-memory users, so the tests do not need a database.
final Map<int, FakeUser> users = <int, FakeUser>{};

class FakeUser extends Model<FakeUser> {
  int? id;
  String? email;
  String? password;

  final Map<String, dynamic> _wheres = <String, dynamic>{};

  FakeUser([this.id, this.email, this.password]) {
    hidden = <String>['password'];
  }

  @override
  Map<String, dynamic> convertToMap(dynamic i) {
    return <String, dynamic>{'id': id, 'email': email, 'password': password};
  }

  @override
  Future<FakeUser?> find(dynamic arg1, [dynamic arg2]) async {
    return users[arg1];
  }

  @override
  QueryBuilder<FakeUser> where(String arg1, [dynamic arg2, dynamic arg3]) {
    _wheres[arg1] = arg2;
    return this;
  }

  @override
  Future<FakeUser?> getFirst() async {
    for (FakeUser u in users.values) {
      bool match = true;
      _wheres.forEach((String key, dynamic value) {
        if (u.convertToMap(u)[key] != value) match = false;
      });
      if (match) return u;
    }
    return null;
  }
}

/// Small request stub. Only `header` and `merge` are used by dox_auth.
class FakeRequest implements IDoxRequest {
  final Map<String, String> _headers;
  final Map<String, dynamic> merged = <String, dynamic>{};

  FakeRequest([this._headers = const <String, String>{}]);

  @override
  String? header(String key) => _headers[key];

  @override
  void merge(Map<String, dynamic> values) => merged.addAll(values);

  @override
  IAuth? auth;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

FakeRequest bearer(String? token) {
  return FakeRequest(<String, String>{'Authorization': 'Bearer $token'});
}

/// Admins live in another table, so the `admin` guard uses its own store.
final Map<int, FakeUser> admins = <int, FakeUser>{};

class FakeAdmin extends FakeUser {
  FakeAdmin([super.id, super.email, super.password]);

  @override
  Future<FakeUser?> find(dynamic arg1, [dynamic arg2]) async => admins[arg1];

  @override
  Future<FakeUser?> getFirst() async {
    for (FakeUser u in admins.values) {
      bool match = true;
      _wheres.forEach((String key, dynamic value) {
        if (u.convertToMap(u)[key] != value) match = false;
      });
      if (match) return u;
    }
    return null;
  }
}

void init({Duration expiresIn = const Duration(hours: 1)}) {
  Auth.initialize(
    AuthConfig(
      defaultGuard: 'web',
      guards: <String, AuthGuard>{
        'web': AuthGuard(
          driver: JwtAuthDriver(
            secret: SecretKey(secret),
            expiresIn: expiresIn,
          ),
          provider: AuthProvider(model: () => FakeUser()),
        ),

        /// same secret on purpose: the guard name must still keep them apart
        'admin': AuthGuard(
          driver: JwtAuthDriver(secret: SecretKey(secret)),
          provider: AuthProvider(model: () => FakeAdmin()),
        ),
      },
    ),
  );
}

/// A fresh memory cache, like a Dox app with a `memory` store.
void freshCache() {
  Dox().cache = CacheManager(
    CacheConfig(
      defaultStore: 'memory',
      stores: <String, Map<String, dynamic>>{
        'memory': <String, dynamic>{'driver': 'memory'},
      },
    ),
  );
}

/// claims that the driver needs in a token made by hand
const Map<String, dynamic> claims = <String, dynamic>{'sub': 1, 'jti': 'j1'};

void main() {
  setUp(() {
    freshCache();
    users
      ..clear()
      ..[1] = FakeUser(1, 'a@dox.dev', Hash.make('secret'));
    admins
      ..clear()
      ..[1] = FakeAdmin(1, 'boss@dox.dev', Hash.make('admin-secret'));
    init();
  });

  group('JwtAuthDriver |', () {
    test('login issues a token with the user id and no user columns', () {
      String? token = Auth().login(users[1]!);
      expect(token, isNotNull);
      JWT jwt = JWT.verify(token!, signingKey);
      // the raw secret (APP_KEY) does not check it
      expect(
        () => JWT.verify(token, SecretKey(secret)),
        throwsA(isA<JWTException>()),
      );
      expect(jwt.payload['sub'], 1);
      // anyone can read the payload, so no user columns are in it
      expect(jwt.payload.containsKey('id'), isFalse);
      expect(jwt.payload.containsKey('email'), isFalse);
      expect(jwt.payload.containsKey('password'), isFalse);
    });

    test('createToken drops every key but the user id', () {
      JwtAuthDriver driver = JwtAuthDriver(secret: SecretKey(secret));
      String token = driver.createToken(<String, dynamic>{
        'sub': 1,
        'email': 'a@dox.dev',
      }, 'web')!;
      Map<String, dynamic> payload = JWT.decode(token).payload;
      expect(payload['sub'], 1);
      expect(payload.containsKey('email'), isFalse);
      // like 3.0.2: the whole user, with the id under the primary key
      Map<String, dynamic> fromJson = JWT
          .decode(driver.createToken(users[1]!.toJson(), 'web')!)
          .payload;
      expect(fromJson['sub'], 1);
      expect(fromJson.containsKey('email'), isFalse);
      expect(
        driver.createToken(<String, dynamic>{'email': 'x'}, 'web'),
        isNull,
      );
    });

    test('verifyToken finds the user for a good token', () async {
      String token = Auth().login(users[1]!)!;
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      expect(auth.isLoggedIn(), isTrue);
      expect(auth.user<FakeUser>()?.email, 'a@dox.dev');
      expect(auth.toJson()?['id'], 1);
    });

    test('verifyToken with no header is not logged in', () async {
      Auth auth = Auth();
      await auth.verifyToken(FakeRequest());
      expect(auth.isLoggedIn(), isFalse);
      expect(auth.user<FakeUser>(), isNull);
    });

    test('verifyToken with an invalid token is not logged in', () async {
      Auth auth = Auth();
      await auth.verifyToken(bearer('not-a-jwt'));
      expect(auth.isLoggedIn(), isFalse);
    });

    test(
      'verifyToken with a token signed by another secret is rejected',
      () async {
        String token = JWT(claims).sign(SecretKey('other-secret'));
        Auth auth = Auth();
        await auth.verifyToken(bearer(token));
        expect(auth.isLoggedIn(), isFalse);
      },
    );

    test('verifyToken with an expired token is rejected', () async {
      init(expiresIn: Duration(seconds: 1));
      String token = Auth().login(users[1]!)!;
      await Future<void>.delayed(Duration(seconds: 2));
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      expect(auth.isLoggedIn(), isFalse);
    });

    test('verifyToken for a deleted user is not logged in', () async {
      String token = Auth().login(users[1]!)!;
      users.clear();
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      expect(auth.isLoggedIn(), isFalse);
    });

    test('attempt with right credentials returns a token', () async {
      Auth auth = Auth();
      String? token = await auth.attempt(<String, dynamic>{
        'email': 'a@dox.dev',
        'password': 'secret',
      });
      expect(token, isNotNull);
      expect(auth.isLoggedIn(), isTrue);
    });

    test('attempt with wrong password returns null', () async {
      Auth auth = Auth();
      String? token = await auth.attempt(<String, dynamic>{
        'email': 'a@dox.dev',
        'password': 'wrong',
      });
      expect(token, isNull);
      expect(auth.isLoggedIn(), isFalse);
    });

    test('attempt with unknown email returns null', () async {
      String? token = await Auth().attempt(<String, dynamic>{
        'email': 'nobody@dox.dev',
        'password': 'secret',
      });
      expect(token, isNull);
    });

    test('an unknown email takes about as long as a wrong password', () async {
      // warm up the isolate code path
      await Auth().attempt(<String, dynamic>{
        'email': 'x@dox.dev',
        'password': 'x',
      });

      Stopwatch unknown = Stopwatch()..start();
      await Auth().attempt(<String, dynamic>{
        'email': 'nobody@dox.dev',
        'password': 'secret',
      });
      unknown.stop();

      Stopwatch wrong = Stopwatch()..start();
      await Auth().attempt(<String, dynamic>{
        'email': 'a@dox.dev',
        'password': 'wrong',
      });
      wrong.stop();

      // both run bcrypt. without it an unknown email answers in ~0 ms.
      expect(
        unknown.elapsedMicroseconds,
        greaterThan(wrong.elapsedMicroseconds ~/ 4),
      );
    });

    test('an empty secret is refused', () {
      expect(() => JwtAuthDriver(secret: SecretKey('')), throwsArgumentError);
      expect(() => JwtAuthDriver(secret: SecretKey('  ')), throwsArgumentError);
    });

    test('a short secret stops production and warns in development', () {
      Env().env['APP_ENV'] = 'production';
      expect(
        () => JwtAuthDriver(secret: SecretKey('short')),
        throwsA(
          isA<ArgumentError>().having(
            (ArgumentError e) => e.message,
            'message',
            allOf(contains('at least 32 bytes'), contains('openssl rand')),
          ),
        ),
      );
      Env().env['APP_ENV'] = 'development';
      expect(
        () => JwtAuthDriver(secret: SecretKey('short')),
        prints(contains('[dox] warning: The JWT secret is 5 bytes')),
      );
      expect(() => JwtAuthDriver(secret: SecretKey(secret)), prints(isEmpty));
      Env().env['APP_ENV'] = 'testing';
      expect(
        () => JwtAuthDriver(secret: SecretKey('short')),
        prints(contains('[dox] warning')),
      );
      Env().env.remove('APP_ENV');
    });

    test('a user with no stored password cannot log in', () async {
      users[2] = FakeUser(2, 'nopass@dox.dev');
      String? token = await Auth().attempt(<String, dynamic>{
        'email': 'nopass@dox.dev',
        'password': 'dox-no-user',
      });
      expect(token, isNull);
    });

    test('attempt without a password returns null', () async {
      String? token = await Auth().attempt(<String, dynamic>{
        'email': 'a@dox.dev',
      });
      expect(token, isNull);
    });

    test('attempt with only a password returns null', () async {
      String? token = await Auth().attempt(<String, dynamic>{
        'password': 'secret',
      });
      expect(token, isNull);
    });

    test('attempt with a non-string password returns null', () async {
      String? token = await Auth().attempt(<String, dynamic>{
        'email': 'a@dox.dev',
        'password': 123,
      });
      expect(token, isNull);
    });
  });

  group('User cache |', () {
    void initCache(Duration? ttl) {
      Auth.initialize(
        AuthConfig(
          defaultGuard: 'web',
          guards: <String, AuthGuard>{
            'web': AuthGuard(
              driver: JwtAuthDriver(
                secret: SecretKey(secret),
                userCacheTtl: ttl,
              ),
              provider: AuthProvider(model: () => FakeUser()),
            ),
          },
        ),
      );
    }

    Future<FakeUser?> userOf(String token) async {
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      return auth.user<FakeUser>();
    }

    test('off by default: a deleted user is seen at once', () async {
      initCache(null);
      String token = Auth().login(users[1]!)!;
      expect(await userOf(token), isNotNull);
      users.clear();
      expect(await userOf(token), isNull);
    });

    test('keeps the user for the ttl, then loads it again', () async {
      initCache(Duration(milliseconds: 300));
      String token = Auth().login(users[1]!)!;
      FakeUser? first = await userOf(token);
      users.clear();
      expect(await userOf(token), same(first));
      await Future<void>.delayed(Duration(milliseconds: 400));
      expect(await userOf(token), isNull);
    });

    test('a bad token is still rejected', () async {
      initCache(Duration(minutes: 1));
      String token = Auth().login(users[1]!)!;
      expect(await userOf(token), isNotNull);
      expect(await userOf('$token-bad'), isNull);
    });
  });

  group('Revoke tokens |', () {
    Future<bool> loggedIn(String token) async {
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      return auth.isLoggedIn();
    }

    test('each token has its own jti', () {
      String a = Auth().login(users[1]!)!;
      String b = Auth().login(users[1]!)!;
      expect(JWT.decode(a).jwtId, isNotEmpty);
      expect(JWT.decode(a).jwtId, isNot(JWT.decode(b).jwtId));
    });

    test('a token without a jti still works', () async {
      String token = JWT(<String, dynamic>{
        'sub': 1,
      }, audience: Audience.one('web')).sign(signingKey);
      expect(await loggedIn(token), isTrue);
    });

    test('a cache that can not be read does not log anyone out', () async {
      Auth.initialize(
        AuthConfig(
          defaultGuard: 'web',
          guards: <String, AuthGuard>{
            'web': AuthGuard(
              driver: JwtAuthDriver(
                secret: SecretKey(secret),
                revocationStore: 'missing',
              ),
              provider: AuthProvider(model: () => FakeUser()),
            ),
          },
        ),
      );
      String token = Auth().login(users[1]!)!;
      late bool result;
      await expectLater(
        () async => result = await loggedIn(token),
        prints(contains('[dox] warning: dox_auth can not read')),
      );
      expect(result, isTrue);
    });

    test('a token used after logout is rejected', () async {
      String token = Auth().login(users[1]!)!;
      String other = Auth().login(users[1]!)!;
      expect(await loggedIn(token), isTrue);

      await Auth().logout(bearer(token));
      expect(await loggedIn(token), isFalse);
      // only this token: another login of the same user still works
      expect(await loggedIn(other), isTrue);
    });

    test('the deny-list entry lives as long as the token', () async {
      init(expiresIn: Duration(minutes: 5));
      String token = Auth().login(users[1]!)!;
      await Auth().logout(bearer(token));
      String jti = JWT.decode(token).jwtId!;
      expect(await Dox().cache.store().has('auth:revoked:$jti'), isTrue);
    });

    test('logout with a bad token does nothing', () async {
      await Auth().logout(bearer('not-a-jwt'));
      await Auth().logout(FakeRequest());
    });

    test('revokeAllTokens rejects older tokens of the user', () async {
      int now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      String old = JWT(<String, dynamic>{
        ...claims,
        'iat': now - 10,
      }, audience: Audience.one('web')).sign(signingKey, noIssueAt: true);
      String adminToken = Auth(guard: 'admin').login(admins[1]!)!;
      expect(await loggedIn(old), isTrue);

      await Auth().revokeAllTokens(1);
      expect(await loggedIn(old), isFalse);

      // a new login after the call works
      expect(await loggedIn(Auth().login(users[1]!)!), isTrue);
      // the same id on another guard is not touched
      Auth admin = Auth(guard: 'admin');
      await admin.verifyToken(bearer(adminToken));
      expect(admin.isLoggedIn(), isTrue);
    });

    test('forgetUser drops a banned user from the user cache', () async {
      JwtAuthDriver driver = JwtAuthDriver(
        secret: SecretKey(secret),
        userCacheTtl: Duration(minutes: 1),
      );
      Auth.initialize(
        AuthConfig(
          defaultGuard: 'web',
          guards: <String, AuthGuard>{
            'web': AuthGuard(
              driver: driver,
              provider: AuthProvider(model: () => FakeUser()),
            ),
          },
        ),
      );
      String token = Auth().login(users[1]!)!;
      expect(await loggedIn(token), isTrue);

      // banned (here: removed). the cache still has the user.
      users.clear();
      expect(await loggedIn(token), isTrue);

      // another isolate or server forgets the user, through the cache
      JwtAuthDriver otherIsolate = JwtAuthDriver(
        secret: SecretKey(secret),
        userCacheTtl: Duration(minutes: 1),
      );
      await otherIsolate.forgetUser(1, 'web');
      expect(await loggedIn(token), isFalse);
    });

    test('forgetUser on this isolate drops the user at once', () async {
      Auth.initialize(
        AuthConfig(
          defaultGuard: 'web',
          guards: <String, AuthGuard>{
            'web': AuthGuard(
              driver: JwtAuthDriver(
                secret: SecretKey(secret),
                userCacheTtl: Duration(minutes: 1),
              ),
              provider: AuthProvider(model: () => FakeUser()),
            ),
          },
        ),
      );
      String token = Auth().login(users[1]!)!;
      expect(await loggedIn(token), isTrue);
      users.clear();
      await Auth().forgetUser(1);
      expect(await loggedIn(token), isFalse);
    });

    test('revoke methods need a JWT guard', () {
      Auth.initialize(
        AuthConfig(
          defaultGuard: 'web',
          guards: <String, AuthGuard>{
            'web': AuthGuard(
              driver: SessionAuthDriver(),
              provider: AuthProvider(model: () => FakeUser()),
            ),
          },
        ),
      );
      expect(() => Auth().revokeAllTokens(1), throwsStateError);
      expect(() => Auth().forgetUser(1), throwsStateError);
    });
  });

  group('Hash rounds |', () {
    test('attempt works with a custom hashRounds', () async {
      users[3] = FakeUser(3, 'low@dox.dev', Hash.make('pw', rounds: 4));
      Auth.initialize(
        AuthConfig(
          defaultGuard: 'web',
          guards: <String, AuthGuard>{
            'web': AuthGuard(
              driver: JwtAuthDriver(secret: SecretKey(secret), hashRounds: 4),
              provider: AuthProvider(model: () => FakeUser()),
            ),
          },
        ),
      );
      expect(
        await Auth().attempt(<String, dynamic>{
          'email': 'low@dox.dev',
          'password': 'pw',
        }),
        isNotNull,
      );
      expect(
        await Auth().attempt(<String, dynamic>{
          'email': 'nobody@dox.dev',
          'password': 'pw',
        }),
        isNull,
      );
    });
  });

  group('JWT expiry |', () {
    test('a token expires after 1 hour by default', () {
      String token = Auth().login(users[1]!)!;
      Map<String, dynamic> payload = JWT.decode(token).payload;
      expect(payload['exp'] - payload['iat'], 3600);
    });

    test('expiresIn can be changed', () {
      init(expiresIn: Duration(minutes: 5));
      String token = Auth().login(users[1]!)!;
      Map<String, dynamic> payload = JWT.decode(token).payload;
      expect(payload['exp'] - payload['iat'], 300);
    });
  });

  group('Named guards |', () {
    test('attempt on a named guard uses its provider', () async {
      Auth admin = Auth(guard: 'admin');
      String? token = await admin.attempt(<String, dynamic>{
        'email': 'boss@dox.dev',
        'password': 'admin-secret',
      });
      expect(token, isNotNull);
      expect(admin.user<FakeUser>()?.email, 'boss@dox.dev');

      /// the default guard does not know this admin
      expect(
        await Auth().attempt(<String, dynamic>{
          'email': 'boss@dox.dev',
          'password': 'admin-secret',
        }),
        isNull,
      );
    });

    test('a token of one guard does not work on another guard', () async {
      String userToken = Auth().login(users[1]!)!;
      String adminToken = Auth(guard: 'admin').login(admins[1]!)!;

      Auth a1 = Auth(guard: 'admin');
      await a1.verifyToken(bearer(userToken));
      expect(a1.isLoggedIn(), isFalse);

      Auth a2 = Auth();
      await a2.verifyToken(bearer(adminToken));
      expect(a2.isLoggedIn(), isFalse);

      Auth a3 = Auth(guard: 'admin');
      await a3.verifyToken(bearer(adminToken));
      expect(a3.user<FakeUser>()?.email, 'boss@dox.dev');
    });

    test('a token with no guard audience is rejected', () async {
      String token = JWT(claims).sign(signingKey);
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      expect(auth.isLoggedIn(), isFalse);
    });

    test('a token signed with the raw secret is rejected', () async {
      String token = JWT(
        claims,
        audience: Audience.one('web'),
      ).sign(SecretKey(secret));
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      expect(auth.isLoggedIn(), isFalse);
    });

    test('a token with another algorithm is rejected', () async {
      JWT jwt = JWT(claims, audience: Audience.one('web'));
      Auth good = Auth();
      await good.verifyToken(bearer(jwt.sign(signingKey)));
      expect(good.isLoggedIn(), isTrue);
      // the right key, but HS512 and not the configured HS256
      Auth other = Auth();
      await other.verifyToken(
        bearer(jwt.sign(signingKey, algorithm: JWTAlgorithm.HS512)),
      );
      expect(other.isLoggedIn(), isFalse);
    });

    test('attempt with a map or a list as the email fails', () async {
      for (dynamic email in <dynamic>[
        <String, dynamic>{'like': '%'},
        <dynamic>['a@dox.dev'],
      ]) {
        String? token = await Auth().attempt(<String, dynamic>{
          'email': email,
          'password': 'secret',
        });
        expect(token, isNull);
      }
    });

    test('AuthMiddleware uses its guard', () async {
      String adminToken = Auth(guard: 'admin').login(admins[1]!)!;
      FakeRequest req = bearer(adminToken);
      await AuthMiddleware(guard: 'admin').handle(req);
      Auth auth = req.auth! as Auth;
      expect(auth.user<FakeUser>()?.email, 'boss@dox.dev');

      expect(
        () => AuthMiddleware().handle(bearer(adminToken)),
        throwsA(isA<UnAuthorizedException>()),
      );
    });

    test('an unknown guard throws', () {
      expect(() => Auth(guard: 'nope').login(users[1]!), throwsArgumentError);
    });
  });

  group('Change APP_KEY |', () {
    const String oldKey = 'old-app-key-0123456789abcdefghijk';
    const String newKey = 'new-app-key-0123456789abcdefghijk';

    /// a token for user 1 on the `web` guard, signed like the driver does
    String oldToken({Duration expiresIn = const Duration(hours: 1)}) {
      JWTKey key = JwtAuthDriver(secret: SecretKey(oldKey)).signingKey;
      return JWT(
        claims,
        audience: Audience.one('web'),
      ).sign(key, expiresIn: expiresIn);
    }

    Future<bool> loggedIn(String token, JwtAuthDriver driver) async {
      Auth.initialize(
        AuthConfig(
          defaultGuard: 'web',
          guards: <String, AuthGuard>{
            'web': AuthGuard(
              driver: driver,
              provider: AuthProvider(model: () => FakeUser()),
            ),
          },
        ),
      );
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      return auth.isLoggedIn();
    }

    void appConfig(List<String> previousKeys) {
      Dox().config = AppConfig(appKey: newKey, previousKeys: previousKeys);
    }

    test('an old-key token works when the key is in previousKeys', () async {
      appConfig(<String>[oldKey]);
      JwtAuthDriver driver = JwtAuthDriver(secret: SecretKey(newKey));
      expect(await loggedIn(oldToken(), driver), isTrue);
    });

    test(
      'an old-key token fails when the key is not in previousKeys',
      () async {
        appConfig(<String>[]);
        JwtAuthDriver driver = JwtAuthDriver(secret: SecretKey(newKey));
        expect(await loggedIn(oldToken(), driver), isFalse);
      },
    );

    test('an expired old-key token is rejected', () async {
      appConfig(<String>[oldKey]);
      String token = oldToken(expiresIn: Duration(seconds: -10));
      JwtAuthDriver driver = JwtAuthDriver(secret: SecretKey(newKey));
      expect(await loggedIn(token, driver), isFalse);
    });

    test('a token that matches no key is rejected', () async {
      appConfig(<String>[oldKey]);
      String token = JWT(
        claims,
        audience: Audience.one('web'),
      ).sign(SecretKey('some-other-key'));
      JwtAuthDriver driver = JwtAuthDriver(secret: SecretKey(newKey));
      expect(await loggedIn(token, driver), isFalse);
    });

    test('new tokens are signed with the current key', () async {
      appConfig(<String>[oldKey]);
      JwtAuthDriver driver = JwtAuthDriver(secret: SecretKey(newKey));
      expect(await loggedIn(oldToken(), driver), isTrue);
      String token = Auth().login(users[1]!)!;
      expect(JWT.verify(token, driver.signingKey).payload['sub'], 1);
      JWTKey old = JwtAuthDriver(secret: SecretKey(oldKey)).signingKey;
      expect(() => JWT.verify(token, old), throwsA(isA<JWTException>()));
    });

    test(
      'previousKeys are not used for a secret that is not APP_KEY',
      () async {
        appConfig(<String>[oldKey]);
        JwtAuthDriver driver = JwtAuthDriver(secret: SecretKey(secret));
        expect(await loggedIn(oldToken(), driver), isFalse);
      },
    );

    test('previousSecrets on the driver works without APP_KEY', () async {
      appConfig(<String>[]);
      JwtAuthDriver driver = JwtAuthDriver(
        secret: SecretKey(secret),
        previousSecrets: <JWTKey>[SecretKey(oldKey)],
      );
      expect(await loggedIn(oldToken(), driver), isTrue);
    });
  });

  group('AuthMiddleware |', () {
    test('rejects a request with no token', () async {
      expect(
        () => AuthMiddleware().handle(FakeRequest()),
        throwsA(isA<UnAuthorizedException>()),
      );
    });

    test('rejects a request with a bad token', () async {
      expect(
        () => AuthMiddleware().handle(bearer('bad.token.here')),
        throwsA(isA<UnAuthorizedException>()),
      );
    });

    test('accepts a request with a good token and merges auth', () async {
      String token = Auth().login(users[1]!)!;
      FakeRequest req = bearer(token);
      IDoxRequest res = await AuthMiddleware().handle(req);
      expect(res, same(req));
      Auth auth = req.auth! as Auth;
      expect(auth.user<FakeUser>()?.id, 1);
    });

    test('UnAuthorizedException is a 401', () {
      UnAuthorizedException e = UnAuthorizedException();
      expect(e.code, 401);
      expect(e.errorCode, 'unauthorized');
      // a map message is sent as it is
      Map<String, String> body = <String, String>{'error': 'login_needed'};
      expect(UnAuthorizedException(message: body).toResponse(), body);
    });
  });

  group('Tokens made before 3.0.3 |', () {
    /// a token made the 3.0.2 way: the whole user, no sub and no jti
    String oldToken({Duration expiresIn = const Duration(hours: 1)}) {
      return JWT(
        users[1]!.toJson(),
        audience: Audience.one('web'),
      ).sign(signingKey, expiresIn: expiresIn);
    }

    Future<FakeUser?> userOf(String token) async {
      Auth auth = Auth();
      await auth.verifyToken(bearer(token));
      return auth.user<FakeUser>();
    }

    test('still works and loads the user', () async {
      String token = oldToken();
      expect(JWT.decode(token).payload.containsKey('jti'), isFalse);
      expect((await userOf(token))?.email, 'a@dox.dev');
    });

    test('expires as normal', () async {
      String token = oldToken(expiresIn: Duration(seconds: 1));
      await Future<void>.delayed(Duration(seconds: 2));
      expect(await userOf(token), isNull);
    });

    test('logout does nothing, like in 3.0.2', () async {
      String token = oldToken();
      await Auth().logout(bearer(token));
      expect(await userOf(token), isNotNull);
    });

    test('revokeAllTokens rejects one with an iat', () async {
      int now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      String token = JWT(<String, dynamic>{
        ...users[1]!.toJson(),
        'iat': now - 10,
      }, audience: Audience.one('web')).sign(signingKey, noIssueAt: true);
      expect(await userOf(token), isNotNull);
      await Auth().revokeAllTokens(1);
      expect(await userOf(token), isNull);
    });

    test('one with no iat works until it expires', () async {
      String token = JWT(
        users[1]!.toJson(),
        audience: Audience.one('web'),
      ).sign(signingKey, noIssueAt: true, expiresIn: Duration(hours: 1));
      await Auth().revokeAllTokens(1);
      expect(await userOf(token), isNotNull);
    });
  });
}
