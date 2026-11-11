// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_core/testing.dart';
import 'package:test/test.dart';

import 'gate_http_test.dart' show useFlags;
import 'jwt_auth_test.dart' show FakeUser, secret, users;

class WebRouter extends Router {
  @override
  List<dynamic> get middleware => <dynamic>[const SessionMiddleware()];

  @override
  void register() {
    Route.post('login', (DoxRequest req) async {
      bool ok = await Auth().attemptSession(
        req,
        req.only(<String>['email', 'password']),
      );
      return ok ? 'in' : 'wrong';
    });
    Route.post('logout', (DoxRequest req) {
      Auth().logout(req);
      return 'out';
    });
    Route.get('me', <dynamic>[
      AuthMiddleware(),
      (DoxRequest req) => req.auth?.user<FakeUser>()?.email,
    ]);
    Route.get('page', <dynamic>[
      AuthMiddleware(redirectTo: '/login'),
      (DoxRequest req) => 'page',
    ]);
    Route.get('page-either', <dynamic>[
      AuthMiddleware(guards: <String>['web', 'api'], redirectTo: '/login'),
      (DoxRequest req) => 'page',
    ]);
    Route.get('either', <dynamic>[
      AuthMiddleware(guards: <String>['web', 'api']),
      (DoxRequest req) => _whoAndGuard(req),
    ]);
    Route.get('either-api-first', <dynamic>[
      AuthMiddleware(guards: <String>['api', 'web']),
      (DoxRequest req) => _whoAndGuard(req),
    ]);
    Route.post('once', (DoxRequest req) async {
      Auth auth = Auth(ip: req.ip());
      bool ok = await auth.once(req.only(<String>['email', 'password']));
      return ok ? 'ok ${auth.currentAccessToken}' : 'wrong';
    });
    Route.get('public', <dynamic>[
      AuthMiddleware(optional: true),
      (DoxRequest req) => req.auth?.user<FakeUser>()?.email ?? 'guest',
    ]);
    Route.get('login-page', <dynamic>[
      GuestMiddleware(redirectTo: '/dashboard'),
      (DoxRequest req) => 'login page',
    ]);
    Route.get('register-page', <dynamic>[
      GuestMiddleware(),
      (DoxRequest req) => 'register page',
    ]);
    Route.post('note', (DoxRequest req) {
      req.session.put('note', 'hi');
      return 'ok';
    });
    Route.get('note', (DoxRequest req) => req.session.get('note') ?? 'none');
    Route.post('logout-others', <dynamic>[
      AuthMiddleware(),
      (DoxRequest req) async {
        try {
          await (req.auth as Auth).logoutOtherDevices(
            req,
            req.input('password') as String,
          );
          return 'done';
        } on UnAuthorizedException catch (error) {
          return '${error.message}';
        } on StateError catch (error) {
          return error.message;
        }
      },
    ]);
    // the app's own password change. `keep` keeps this session logged in.
    Route.post('change-password', <dynamic>[
      AuthMiddleware(),
      (DoxRequest req) async {
        FakeUser user = req.auth!.user<FakeUser>()!;
        user.password = Hash.make(req.input('password') as String, rounds: 4);
        await user.save();
        if (req.input('keep') == true) {
          Auth().updateSessionPasswordHash(req, user);
        }
        return 'changed';
      },
    ]);
    // a user that is not logged in to this session
    Route.post('keep-other-user', <dynamic>[
      AuthMiddleware(),
      (DoxRequest req) {
        try {
          Auth().updateSessionPasswordHash(req, users[1]!);
          return 'kept';
        } on ArgumentError catch (error) {
          return '${error.message}';
        }
      },
    ]);
    // logoutOtherDevices with no AuthMiddleware, on the guard of the body
    Route.post('logout-others-bare', (DoxRequest req) async {
      try {
        await Auth(guard: req.input('guard') as String?)
            .logoutOtherDevices(req, 'secret');
        return 'done';
      } on UnAuthorizedException {
        return 'unauthorized';
      } on StateError {
        return 'state error';
      }
    });
    // log in user 3 on the web and web2 guards, with no password check
    Route.post('login-both', (DoxRequest req) {
      Auth().loginSession(req, users[3]!);
      Auth(guard: 'web2').loginSession(req, users[3]!);
      return 'in';
    });
    Route.get('me2', <dynamic>[
      AuthMiddleware(guard: 'web2'),
      (DoxRequest req) => req.auth?.user<FakeUser>()?.email,
    ]);
    // a login from before this feature: the id only, no password hash
    Route.post('old-login', (DoxRequest req) {
      req.session.put(SessionAuthDriver.sessionKey('web'), 2);
      return 'in';
    });
    Route.get('jwt', (DoxRequest req) {
      Auth(guard: 'api').logout(req);
      return 'no';
    });
  }
}

/// Acts like a dox_orm model: `find` loads a new copy of the row, and
/// `toMap(original: true)` gives the row as it was loaded, not changed
/// by `save()`. `save()` writes the fields back to [users].
class FreshUser extends FakeUser {
  FreshUser([super.id, super.email, super.password]) {
    if (id != null) originalMap = convertToMap(this);
  }

  @override
  Future<FakeUser?> find(dynamic arg1, [dynamic arg2]) async {
    FakeUser? row = users[arg1];
    return row == null ? null : FreshUser(row.id, row.email, row.password);
  }

  @override
  Future<bool> save() async {
    if (!FakeUser.saveOk) return false;
    users[id!] = FreshUser(id, email, password);
    return true;
  }
}

/// the email of the user and the guard that let it in
String _whoAndGuard(DoxRequest req) {
  Auth auth = req.auth as Auth;
  return '${auth.user<FakeUser>()?.email} ${auth.guard}';
}

/// the headers of a JSON client and of an XHR client
const List<Map<String, String>> _jsonHeaders = <Map<String, String>>[
  <String, String>{'accept': 'application/json'},
  <String, String>{'x-requested-with': 'XMLHttpRequest'},
];

/// keeps the cookies of every answer, like a browser
class Browser {
  Browser(this.client);

  final DoxTestClient client;
  final Map<String, String> cookies = <String, String>{};

  Future<TestResponse> get(String path) {
    return _keep(client.withCookies(cookies).get(path));
  }

  Future<TestResponse> post(String path, [Object? body]) {
    return _keep(client.withCookies(cookies).post(path, body: body));
  }

  Future<TestResponse> _keep(Future<TestResponse> pending) async {
    TestResponse res = await pending;
    cookies.addAll(res.cookies);
    return res;
  }
}

/// The same login routes, but with no SessionMiddleware.
/// They answer with the error message, so the test can read it.
class NoSessionRouter extends Router {
  @override
  String get prefix => 'bare';

  @override
  void register() {
    Route.post('login', (DoxRequest req) async {
      try {
        bool ok = await Auth().attemptSession(
          req,
          req.only(<String>['email', 'password']),
        );
        return '$ok';
      } on StateError catch (error) {
        return error.message;
      }
    });
    Route.post('logout', (DoxRequest req) {
      try {
        Auth().logout(req);
        return 'no error';
      } on StateError catch (error) {
        return error.message;
      }
    });
  }
}

void main() {
  late DoxTestClient client;

  setUpAll(() async {
    users[1] = FakeUser(1, 'a@dox.dev', Hash.make('secret', rounds: 4));
    Auth.initialize(
      AuthConfig(
        defaultGuard: 'web',
        guards: <String, AuthGuard>{
          'web': AuthGuard(
            driver: SessionAuthDriver(hashRounds: 4),
            provider: AuthProvider(model: () => FreshUser()),
          ),
          'web2': AuthGuard(
            driver: SessionAuthDriver(hashRounds: 4),
            provider: AuthProvider(model: () => FreshUser()),
          ),
          'api': AuthGuard(
            driver: JwtAuthDriver(secret: SecretKey(secret)),
            provider: AuthProvider(model: () => FakeUser()),
          ),
        },
      ),
    );
    client = await DoxTestClient.start(
      AppConfig(
        appKey: secret,
        routers: <Router>[WebRouter(), NoSessionRouter()],
        // memory, so the login throttle counts do not stay on disk
        cache: const CacheConfig(
          defaultStore: 'memory',
          stores: <String, Map<String, dynamic>>{
            'memory': <String, dynamic>{'driver': 'memory'},
          },
        ),
      ),
    );
  });

  tearDownAll(() async {
    await client.close();
  });

  test('login keeps the user in the session until logout', () async {
    Browser browser = Browser(client);
    expect((await browser.get('/me')).status, 401);

    TestResponse login = await browser.post('/login', <String, dynamic>{
      'email': 'a@dox.dev',
      'password': 'secret',
    });
    expect(login.body, 'in');
    expect((await browser.get('/me')).body, 'a@dox.dev');

    expect((await browser.post('/logout')).body, 'out');
    expect((await browser.get('/me')).status, 401);
  });

  test('logout removes all session data and gives a new session', () async {
    Browser browser = Browser(client);
    await browser.post('/login', <String, dynamic>{
      'email': 'a@dox.dev',
      'password': 'secret',
    });
    await browser.post('/note');
    expect((await browser.get('/note')).body, 'hi');
    Map<String, String> before = Map<String, String>.of(browser.cookies);

    await browser.post('/logout');
    expect((await browser.get('/me')).status, 401);
    expect((await browser.get('/note')).body, 'none');
    expect(browser.cookies, isNot(equals(before)));
  });

  test('logout with no login is fine', () async {
    Browser browser = Browser(client);
    expect((await browser.post('/logout')).body, 'out');
    expect((await browser.get('/me')).status, 401);
  });

  test('a wrong password does not log in', () async {
    Browser browser = Browser(client);
    TestResponse login = await browser.post('/login', <String, dynamic>{
      'email': 'a@dox.dev',
      'password': 'nope',
    });
    expect(login.body, 'wrong');
    expect((await browser.get('/me')).status, 401);
  });

  test('with Auth.throttle on, too many wrong logins give 429', () async {
    Auth.throttle = LoginThrottle(maxAttempts: 2);
    addTearDown(() => Auth.throttle = null);
    Map<String, dynamic> wrong = <String, dynamic>{
      'email': 'throttle@dox.dev',
      'password': 'nope',
    };
    expect((await client.post('/login', body: wrong)).body, 'wrong');
    expect((await client.post('/login', body: wrong)).body, 'wrong');
    TestResponse blocked = await client.post('/login', body: wrong);
    expect(blocked.status, 429);
    expect(int.parse(blocked.header('retry-after')!), inInclusiveRange(1, 60));
  });

  test('redirectTo sends a guest to the login page', () async {
    TestResponse res = await client.get('/page');
    expect(res.status, 302);
    expect(res.header('location'), '/login');
  });

  test('redirectTo sends a JSON or XHR guest to the login page too', () async {
    for (Map<String, String> headers in _jsonHeaders) {
      TestResponse res = await client.get('/page', headers: headers);
      expect(res.status, 302);
      expect(res.header('location'), '/login');
    }
  });

  test('with jsonNoRedirect on, a JSON or XHR guest gets 401', () async {
    useFlags(const AuthFlags(jsonNoRedirect: true));
    for (Map<String, String> headers in _jsonHeaders) {
      expect((await client.get('/page', headers: headers)).status, 401);
    }
    // a page request and an Inertia request still get the redirect
    TestResponse page = await client.get('/page');
    expect(page.status, 302);
    expect(page.header('location'), '/login');
    TestResponse inertia = await client.get(
      '/page',
      headers: <String, String>{
        'accept': 'application/json',
        'x-inertia': 'true',
      },
    );
    expect(inertia.status, 302);
  });

  test('jsonNoRedirect with several guards: 401 after all fail', () async {
    expect(
      (await client.get('/page-either', headers: _jsonHeaders.first)).status,
      302,
    );
    useFlags(const AuthFlags(jsonNoRedirect: true));
    for (Map<String, String> headers in _jsonHeaders) {
      expect((await client.get('/page-either', headers: headers)).status, 401);
    }
    TestResponse page = await client.get('/page-either');
    expect(page.status, 302);
    expect(page.header('location'), '/login');
  });

  test('AuthFlags.all through AuthConfig turns on every flag', () {
    useFlags(const AuthFlags.all());
    expect(AuthEngine().flags.forbidGuest, isTrue);
    expect(AuthEngine().flags.jsonNoRedirect, isTrue);
  });

  test('AuthFlags.all turns on every flag', () {
    expect(const AuthFlags().forbidGuest, isFalse);
    expect(const AuthFlags().jsonNoRedirect, isFalse);
    expect(const AuthFlags.all().forbidGuest, isTrue);
    expect(const AuthFlags.all().jsonNoRedirect, isTrue);
    expect(const AuthFlags().endSessionsOnPasswordChange, isFalse);
    expect(const AuthFlags.all().endSessionsOnPasswordChange, isTrue);
  });

  test('optional auth lets a guest in and sets the user after login', () async {
    Browser browser = Browser(client);
    expect((await browser.get('/public')).body, 'guest');
    await browser.post('/login', <String, dynamic>{
      'email': 'a@dox.dev',
      'password': 'secret',
    });
    expect((await browser.get('/public')).body, 'a@dox.dev');
  });

  test('GuestMiddleware lets a guest in, and stops a user', () async {
    Browser browser = Browser(client);
    expect((await browser.get('/login-page')).body, 'login page');
    expect((await browser.get('/register-page')).body, 'register page');
    await browser.post('/login', <String, dynamic>{
      'email': 'a@dox.dev',
      'password': 'secret',
    });
    TestResponse page = await browser.get('/login-page');
    expect(page.status, 302);
    expect(page.header('location'), '/dashboard');
    expect((await browser.get('/register-page')).status, 403);
  });

  test(
    'without SessionMiddleware, a right password gives a clear error',
    () async {
      TestResponse ok = await client.post(
        '/bare/login',
        body: <String, dynamic>{'email': 'a@dox.dev', 'password': 'secret'},
      );
      expect(ok.body, contains('Add SessionMiddleware()'));
      // a wrong password gives false, like in 3.0.2
      TestResponse wrong = await client.post(
        '/bare/login',
        body: <String, dynamic>{'email': 'a@dox.dev', 'password': 'nope'},
      );
      expect(wrong.body, 'false');
      TestResponse out = await client.post('/bare/logout');
      expect(out.body, contains('Add SessionMiddleware()'));
    },
  );

  group('userFromSession', () {
    test('gives the user of a logged in session cookie', () async {
      Browser browser = Browser(client);
      await browser.post('/login', <String, String>{
        'email': 'a@dox.dev',
        'password': 'secret',
      });
      Session session = await const SessionMiddleware().fromCookie(
        browser.cookies['dox_session'],
      );
      Auth auth = Auth();
      FakeUser? user = await auth.userFromSession<FakeUser>(session);
      expect(user?.email, 'a@dox.dev');
      expect(auth.isLoggedIn(), isTrue);
    });

    test('gives null after logout, for a guest, or a changed cookie', () async {
      Browser browser = Browser(client);
      await browser.post('/note');
      Session guest = await const SessionMiddleware().fromCookie(
        browser.cookies['dox_session'],
      );
      expect(await Auth().userFromSession<FakeUser>(guest), isNull);

      await browser.post('/login', <String, String>{
        'email': 'a@dox.dev',
        'password': 'secret',
      });
      String raw = browser.cookies['dox_session']!;
      String changed =
          raw.substring(0, raw.length - 2) + (raw.endsWith('AA') ? 'BB' : 'AA');
      Session bad = await const SessionMiddleware().fromCookie(changed);
      expect(await Auth().userFromSession<FakeUser>(bad), isNull);

      await browser.post('/logout');
      Session out = await const SessionMiddleware().fromCookie(
        browser.cookies['dox_session'],
      );
      expect(await Auth().userFromSession<FakeUser>(out), isNull);
    });

    test('needs a session guard', () {
      expect(
        () => Auth(guard: 'api').userFromSession<FakeUser>(Session()),
        throwsStateError,
      );
    });
  });

  test('session methods on a JWT guard throw', () async {
    expect((await client.get('/jwt')).status, 500);
  });

  test(
    'AuthMiddleware with several guards takes the first good login',
    () async {
      Browser browser = Browser(client);
      expect((await browser.get('/either')).status, 401);
      await browser.post('/login', <String, dynamic>{
        'email': 'a@dox.dev',
        'password': 'secret',
      });
      expect((await browser.get('/either')).body, 'a@dox.dev web');

      String token = Auth(guard: 'api').login(users[1]!)!;
      TestResponse jwt = await client.withToken(token).get('/either');
      expect(jwt.body, 'a@dox.dev api');
    },
  );

  test('a bad bearer token does not stop a good session login', () async {
    Browser browser = Browser(client);
    await browser.post('/login', <String, dynamic>{
      'email': 'a@dox.dev',
      'password': 'secret',
    });
    TestResponse res = await client
        .withCookies(browser.cookies)
        .withToken('not-a-token')
        .get('/either-api-first');
    expect(res.status, 200);
    expect(res.body, 'a@dox.dev web');
  });

  test('once() counts in the throttle and leaves the session empty', () async {
    Auth.throttle = LoginThrottle(maxAttempts: 2);
    addTearDown(() => Auth.throttle = null);
    Browser browser = Browser(client);
    TestResponse ok = await browser.post('/once', <String, dynamic>{
      'email': 'a@dox.dev',
      'password': 'secret',
    });
    expect(ok.body, 'ok null');
    expect((await browser.get('/me')).status, 401);

    Map<String, dynamic> wrong = <String, dynamic>{
      'email': 'once@dox.dev',
      'password': 'nope',
    };
    expect((await browser.post('/once', wrong)).body, 'wrong');
    expect((await browser.post('/once', wrong)).body, 'wrong');
    expect((await browser.post('/once', wrong)).status, 429);
  });

  group('password change and logoutOtherDevices', () {
    Map<String, dynamic> login = <String, dynamic>{
      'email': 'b@dox.dev',
      'password': 'secret',
    };

    setUp(() {
      users[2] = FakeUser(2, 'b@dox.dev', Hash.make('secret', rounds: 4));
      users[3] = FakeUser(3, 'c@dox.dev');
    });

    Future<Session> sessionOf(Browser browser) {
      return const SessionMiddleware().fromCookie(
        browser.cookies['dox_session'],
      );
    }

    Future<Browser> loggedIn() async {
      Browser browser = Browser(client);
      expect((await browser.post('/login', login)).body, 'in');
      return browser;
    }

    test('logoutOtherDevices ends other sessions, keeps this one', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      Browser phone = await loggedIn();
      Browser laptop = await loggedIn();
      String oldHash = users[2]!.password!;

      TestResponse res = await laptop.post('/logout-others', <String, String>{
        'password': 'secret',
      });
      expect(res.body, 'done');
      expect(users[2]!.password, isNot(oldHash));
      expect(Hash.verify('secret', users[2]!.password!), isTrue);

      // the next requests load the user again, with the new hash
      expect((await laptop.get('/me')).body, 'b@dox.dev');
      expect((await laptop.get('/me')).body, 'b@dox.dev');
      expect((await phone.get('/me')).status, 401);
      // the same password still logs in
      expect((await phone.post('/login', login)).body, 'in');
    });

    test('logoutOtherDevices with a wrong password changes nothing', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      Browser phone = await loggedIn();
      Browser laptop = await loggedIn();
      String oldHash = users[2]!.password!;

      TestResponse res = await laptop.post('/logout-others', <String, String>{
        'password': 'nope',
      });
      expect(res.body, contains('does not match'));
      expect(users[2]!.password, oldHash);
      expect((await phone.get('/me')).body, 'b@dox.dev');
    });

    test('logoutOtherDevices needs the flag', () async {
      Browser laptop = await loggedIn();
      String oldHash = users[2]!.password!;
      TestResponse res = await laptop.post('/logout-others', <String, String>{
        'password': 'secret',
      });
      expect(res.body, contains('endSessionsOnPasswordChange'));
      expect(users[2]!.password, oldHash);
    });

    test('flag off: a password change keeps all sessions', () async {
      Browser phone = await loggedIn();
      Browser laptop = await loggedIn();
      // login writes nothing new
      Session session = await sessionOf(phone);
      expect(session.has(SessionAuthDriver.passwordHashKey('web')), isFalse);
      await laptop.post('/change-password', <String, String>{
        'password': 'new',
      });
      expect((await phone.get('/me')).body, 'b@dox.dev');
      expect((await laptop.get('/me')).body, 'b@dox.dev');
    });

    test('flag on: a password change ends the sessions', () async {
      useFlags(const AuthFlags.all());
      Browser phone = await loggedIn();
      Browser laptop = await loggedIn();
      Browser tablet = await loggedIn();
      await laptop.post('/change-password', <String, String>{
        'password': 'new',
      });
      expect((await phone.get('/me')).status, 401);
      expect((await laptop.get('/me')).status, 401);
      expect((await tablet.get('/me')).status, 401);
    });

    test('flag on: updateSessionPasswordHash keeps this session', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      Browser phone = await loggedIn();
      Browser laptop = await loggedIn();
      await laptop.post('/change-password', <String, dynamic>{
        'password': 'new',
        'keep': true,
      });
      // the next requests load the user again, with the new hash
      expect((await laptop.get('/me')).body, 'b@dox.dev');
      expect((await laptop.get('/me')).body, 'b@dox.dev');
      expect((await phone.get('/me')).status, 401);
    });

    test('flag on: a session with no stored hash is kept', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      Browser old = Browser(client);
      await old.post('/old-login');
      expect((await old.get('/me')).body, 'b@dox.dev');
      // the first check stores the hash, so a later change ends it
      users[2]!.password = Hash.make('new', rounds: 4);
      expect((await old.get('/me')).status, 401);
    });

    test('a save() stopped by a hook changes nothing', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      FakeUser.saveOk = false;
      addTearDown(() => FakeUser.saveOk = true);
      Browser phone = await loggedIn();
      Browser laptop = await loggedIn();
      String oldHash = users[2]!.password!;
      Session before = await sessionOf(laptop);

      TestResponse res = await laptop.post('/logout-others', <String, String>{
        'password': 'secret',
      });
      expect(res.body, contains('could not save'));
      expect(users[2]!.password, oldHash);
      expect((await phone.get('/me')).body, 'b@dox.dev');
      expect((await laptop.get('/me')).body, 'b@dox.dev');
      Session after = await sessionOf(laptop);
      String key = SessionAuthDriver.passwordHashKey('web');
      expect(after.get(key), before.get(key));
    });

    test('flag on: setting a first password ends old sessions', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      Browser browser = Browser(client);
      await browser.post('/login-both');
      expect((await browser.get('/me')).body, 'c@dox.dev');
      users[3]!.password = Hash.make('secret', rounds: 4);
      expect((await browser.get('/me')).status, 401);
    });

    test('two guards keep separate keys', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      Browser browser = Browser(client);
      await browser.post('/login-both');
      Session session = await sessionOf(browser);
      expect(session.get(SessionAuthDriver.passwordHashKey('web')), isNotNull);
      expect(session.get(SessionAuthDriver.passwordHashKey('web2')), isNotNull);
      // web2 ends on its own when its key is wrong
      session.put(SessionAuthDriver.passwordHashKey('web2'), 'wrong');
      expect(
        await Auth(guard: 'web2').userFromSession<FakeUser>(session),
        isNull,
      );
      Session fresh = await sessionOf(browser);
      fresh.put(SessionAuthDriver.passwordHashKey('web2'), 'wrong');
      expect(
        (await Auth().userFromSession<FakeUser>(fresh))?.email,
        'c@dox.dev',
      );
    });

    test('logoutOtherDevices: a guest or a non-session guard throws', () async {
      useFlags(const AuthFlags(endSessionsOnPasswordChange: true));
      Browser guest = Browser(client);
      expect((await guest.post('/logout-others-bare')).body, 'unauthorized');
      Browser user = await loggedIn();
      expect((await user.post('/logout-others-bare')).body, 'done');
      expect(
        (await user.post('/logout-others-bare', <String, String>{
          'guard': 'api',
        })).body,
        'state error',
      );
    });

    test('updateSessionPasswordHash refuses another user', () async {
      Browser browser = await loggedIn();
      expect(
        (await browser.post('/keep-other-user')).body,
        contains('not the user logged in'),
      );
    });
  });

  test('AuthMiddleware takes guard or guards, not both', () {
    expect(
      () => AuthMiddleware(guard: 'web', guards: <String>['api']),
      throwsArgumentError,
    );
    expect(() => AuthMiddleware(guards: <String>[]), throwsArgumentError);
  });

  test('check() is isLoggedIn(), once() gives a bool and no token', () async {
    Auth jwt = Auth(guard: 'api');
    expect(jwt.check(), isFalse);
    expect(
      await jwt.once(<String, dynamic>{
        'email': 'a@dox.dev',
        'password': 'nope',
      }),
      isFalse,
    );
    expect(jwt.check(), isFalse);
    expect(
      await jwt.once(<String, dynamic>{
        'email': 'a@dox.dev',
        'password': 'secret',
      }),
      isTrue,
    );
    expect(jwt.check(), isTrue);
    expect(jwt.user<FakeUser>()?.email, 'a@dox.dev');

    // works on a session guard too, with no session
    expect(
      await Auth().once(<String, dynamic>{
        'email': 'a@dox.dev',
        'password': 'secret',
      }),
      isTrue,
    );
  });
}
