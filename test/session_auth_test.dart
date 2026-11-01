// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_core/testing.dart';
import 'package:test/test.dart';

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
    Route.post('note', (DoxRequest req) {
      req.session.put('note', 'hi');
      return 'ok';
    });
    Route.get('note', (DoxRequest req) => req.session.get('note') ?? 'none');
    Route.get('jwt', (DoxRequest req) {
      Auth(guard: 'api').logout(req);
      return 'no';
    });
  }
}

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
        await Auth().attemptSession(
          req,
          req.only(<String>['email', 'password']),
        );
        return 'no error';
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
            provider: AuthProvider(model: () => FakeUser()),
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

  test(
    'without SessionMiddleware, session login fails with a clear error',
    () async {
      // the right and the wrong password both fail, so the missing
      // middleware is never hidden behind a "wrong password"
      for (String password in <String>['secret', 'nope']) {
        TestResponse res = await client.post(
          '/bare/login',
          body: <String, dynamic>{'email': 'a@dox.dev', 'password': password},
        );
        expect(res.body, contains('Add SessionMiddleware()'));
      }
      TestResponse out = await client.post('/bare/logout');
      expect(out.body, contains('Add SessionMiddleware()'));
    },
  );

  test('session methods on a JWT guard throw', () async {
    expect((await client.get('/jwt')).status, 500);
  });
}
