// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_core/testing.dart';
import 'package:test/test.dart';

import 'custom_auth_test.dart' show ApiKeyAuthDriver;
import 'jwt_auth_test.dart' show FakeUser, secret, users;

class Post {
  final int id;
  final int userId;

  Post(this.id, this.userId);
}

final Map<int, Post> posts = <int, Post>{1: Post(1, 1), 2: Post(2, 2)};

class PostPolicy extends Policy<FakeUser, Post> {
  bool create(FakeUser user) => user.id == 1;

  bool update(FakeUser user, Post post) => post.userId == user.id;

  @override
  Map<String, Function> get abilities => <String, Function>{
    'create': create,
    'update': update,
  };
}

class GateRouter extends Router {
  @override
  void register() {
    Route.bind<Post>('post', (String id) => posts[int.tryParse(id)]);

    AuthMiddleware auth = AuthMiddleware(guard: 'api');
    Route.get('admin', <dynamic>[
      auth,
      const Can('admin'),
      (DoxRequest r) => 'ok',
    ]);
    Route.get('news', <dynamic>[
      const Can('read-news'),
      (DoxRequest r) => 'news',
    ]);
    Route.post('posts', <dynamic>[
      auth,
      const Can('create', subject: Post),
      (DoxRequest r) => 'made',
    ]);
    Route.put('posts/{post}', <dynamic>[
      auth,
      const Can('update', param: 'post'),
      (DoxRequest req, Post post) => 'updated ${post.id}',
    ]);
    // the request helpers
    Route.get('check/{post}', <dynamic>[
      auth,
      (DoxRequest req, Post post) async {
        bool can = await req.can('update', post);
        bool cannot = await req.cannot('update', post);
        await req.authorize('update', post);
        return '$can $cannot';
      },
    ]);
    Route.get('guest-check', (DoxRequest req) async {
      await req.authorize('admin');
      return 'ok';
    });
  }
}

void main() {
  late DoxTestClient client;

  setUpAll(() async {
    users[1] = FakeUser(1, 'a@dox.dev', 'x');
    users[2] = FakeUser(2, 'b@dox.dev', 'x');
    Auth.initialize(
      AuthConfig(
        defaultGuard: 'api',
        guards: <String, AuthGuard>{
          'api': AuthGuard(
            driver: ApiKeyAuthDriver(),
            provider: AuthProvider(model: () => FakeUser()),
          ),
        },
      ),
    );
    Gate.flush();
    Gate.define('admin', (FakeUser user, _) => user.id == 1);
    Gate.define('read-news', (FakeUser? user, _) => true);
    Gate.policy<Post>(PostPolicy());
    client = await DoxTestClient.start(
      AppConfig(appKey: secret, routers: <Router>[GateRouter()]),
    );
  });

  tearDownAll(() async {
    await client.close();
    Gate.flush();
  });

  DoxTestClient as(String email) => client.withToken(email);

  test('Can with a gate: 401 for a guest, 403 when denied', () async {
    expect((await client.get('/admin')).status, 401);
    expect((await as('b@dox.dev').get('/admin')).status, 403);
    TestResponse ok = await as('a@dox.dev').get('/admin');
    expect(ok.status, 200);
    expect(ok.body, 'ok');
  });

  test('a gate with a nullable user lets guests in', () async {
    TestResponse res = await client.get('/news');
    expect(res.status, 200);
    expect(res.body, 'news');
  });

  test('Can with a type subject uses the policy', () async {
    expect((await as('a@dox.dev').post('/posts')).status, 200);
    expect((await as('b@dox.dev').post('/posts')).status, 403);
  });

  test('Can with a param uses the bound model', () async {
    TestResponse ok = await as('a@dox.dev').put('/posts/1');
    expect(ok.status, 200);
    expect(ok.body, 'updated 1');

    TestResponse denied = await as('a@dox.dev').put('/posts/2');
    denied.expectStatus(403).expectJson(<String, dynamic>{
      'code': 'forbidden',
      'message': 'Forbidden',
    });

    expect((await as('a@dox.dev').put('/posts/99')).status, 404);
    expect((await client.put('/posts/1')).status, 401);
  });

  test('req.can, req.cannot and req.authorize', () async {
    TestResponse ok = await as('a@dox.dev').get('/check/1');
    expect(ok.body, 'true false');
    expect((await as('a@dox.dev').get('/check/2')).status, 403);
  });

  test('req.authorize gives 401 for a guest', () async {
    expect((await client.get('/guest-check')).status, 401);
  });
}
