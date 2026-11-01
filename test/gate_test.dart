// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:test/test.dart';

class User {
  final int id;
  final bool admin;

  User(this.id, {this.admin = false});
}

class Post {
  final int userId;
  final bool published;

  Post(this.userId, {this.published = false});
}

class Comment {}

class PostPolicy extends Policy<User, Post> {
  bool create(User user) => user.id < 100;

  Future<bool> update(User user, Post post) async => post.userId == user.id;

  GateResponse delete(User user, Post post) {
    if (post.published) return const GateResponse.deny('It is published');
    return GateResponse.from(post.userId == user.id);
  }

  @override
  Map<String, Function> get abilities => <String, Function>{
    'create': create,
    'update': update,
    'delete': delete,
  };
}

class GuestPostPolicy extends Policy<User?, Post> {
  bool view(User? user, Post post) => post.published;

  @override
  Map<String, Function> get abilities => <String, Function>{'view': view};
}

class BadPolicy extends Policy<User, Post> {
  bool wrong(String text) => true;

  @override
  Map<String, Function> get abilities => <String, Function>{'wrong': wrong};
}

void main() {
  User ada = User(1);
  User bob = User(2);
  Post post = Post(1);

  setUp(Gate.flush);

  group('gates', () {
    test('a gate with a subject', () async {
      Gate.define('update-post', (User user, Post p) => p.userId == user.id);
      expect(await Gate.allows(ada, 'update-post', post), isTrue);
      expect(await Gate.denies(bob, 'update-post', post), isTrue);
    });

    test('a gate with no subject uses _', () async {
      Gate.define('create-post', (User user, _) => user.id == 1);
      expect(await Gate.allows(ada, 'create-post'), isTrue);
      expect(await Gate.allows(bob, 'create-post'), isFalse);
    });

    test('an async gate', () async {
      Gate.define('slow', (User user, _) async => true);
      expect(await Gate.allows(ada, 'slow'), isTrue);
    });

    test('an unknown ability is denied', () async {
      expect(await Gate.allows(ada, 'nope'), isFalse);
    });

    test('a wrong subject or user type is denied', () async {
      Gate.define('update-post', (User user, Post p) => true);
      expect(await Gate.allows(ada, 'update-post', Comment()), isFalse);
      expect(await Gate.allows(ada, 'update-post'), isFalse);
      expect(await Gate.allows('text', 'update-post', post), isFalse);
    });

    test('a guest is denied, unless the user type is nullable', () async {
      Gate.define('edit', (User user, Post p) => true);
      Gate.define('view', (User? user, Post p) => p.published);
      expect(await Gate.allows(null, 'edit', post), isFalse);
      expect(await Gate.allows(null, 'view', Post(1, published: true)), isTrue);
      expect(await Gate.allows(null, 'view', post), isFalse);
    });

    test('authorize throws 403 with the deny reason', () async {
      Gate.define('ok', (User user, _) => true);
      Gate.define('locked', (User user, _) => const GateResponse.deny('Wait'));
      await Gate.authorize(ada, 'ok');
      await expectLater(
        Gate.authorize(ada, 'locked'),
        throwsA(
          isA<ForbiddenHttpException>()
              .having((ForbiddenHttpException e) => e.code, 'code', 403)
              .having((ForbiddenHttpException e) => e.message, 'msg', 'Wait'),
        ),
      );
      GateResponse res = await Gate.inspect(ada, 'locked');
      expect(res.denied, isTrue);
      expect(res.message, 'Wait');
    });

    test('a check that gives something else is an error', () async {
      Gate.define('bad', (User user, _) => 'yes');
      await expectLater(Gate.allows(ada, 'bad'), throwsStateError);
    });

    test('any and all', () async {
      Gate.define('a', (User user, _) => true);
      Gate.define('b', (User user, _) => false);
      expect(await Gate.any(ada, <String>['a', 'b']), isTrue);
      expect(await Gate.any(ada, <String>['b']), isFalse);
      expect(await Gate.all(ada, <String>['a', 'b']), isFalse);
      expect(await Gate.all(ada, <String>['a']), isTrue);
    });
  });

  group('before and after', () {
    test('before decides when it gives non-null', () async {
      Gate.define('update-post', (User user, Post p) => p.userId == user.id);
      Gate.before((User user, String ability) => user.admin ? true : null);
      expect(
        await Gate.allows(User(9, admin: true), 'update-post', post),
        isTrue,
      );
      expect(await Gate.allows(User(9), 'update-post', post), isFalse);
      // also for an ability with no gate
      expect(await Gate.allows(User(9, admin: true), 'nope'), isTrue);
    });

    test('before can deny', () async {
      Gate.define('a', (User user, _) => true);
      Gate.before((User user, String ability) => false);
      expect(await Gate.allows(ada, 'a'), isFalse);
    });

    test('a before hook for User skips guests', () async {
      Gate.define('view', (User? user, _) => true);
      Gate.before((User user, String ability) => false);
      expect(await Gate.allows(null, 'view'), isTrue);
    });

    test('after sees every answer', () async {
      List<String> log = <String>[];
      Gate.define('a', (User user, _) => true);
      Gate.after((User user, String ability, GateResponse res) {
        log.add('${user.id} $ability ${res.allowed}');
      });
      await Gate.allows(ada, 'a');
      await Gate.allows(bob, 'nope');
      expect(log, <String>['1 a true', '2 nope false']);
    });
  });

  group('policies', () {
    setUp(() => Gate.policy<Post>(PostPolicy()));

    test('a method with the model', () async {
      expect(await Gate.allows(ada, 'update', post), isTrue);
      expect(await Gate.allows(bob, 'update', post), isFalse);
    });

    test('a method with no model takes the type', () async {
      expect(await Gate.allows(ada, 'create', Post), isTrue);
      expect(await Gate.allows(User(500), 'create', Post), isFalse);
    });

    test('a GateResponse reason from a policy', () async {
      GateResponse res = await Gate.inspect(
        ada,
        'delete',
        Post(1, published: true),
      );
      expect(res.message, 'It is published');
      expect(await Gate.allows(ada, 'delete', post), isTrue);
    });

    test('a guest is denied by a Policy<User, ...>', () async {
      expect(await Gate.allows(null, 'update', post), isFalse);
    });

    test('a nullable user policy lets guests in', () async {
      Gate.policy<Post>(GuestPostPolicy());
      expect(await Gate.allows(null, 'view', Post(1, published: true)), isTrue);
      expect(await Gate.allows(null, 'view', post), isFalse);
    });

    test('a missing method uses the gate with that name', () async {
      Gate.define('share', (User user, Post p) => true);
      expect(await Gate.allows(ada, 'share', post), isTrue);
    });

    test('a model method without a model is denied', () async {
      expect(await Gate.allows(ada, 'update', Post), isFalse);
    });

    test('Gate.before runs before the policy', () async {
      Gate.before((User user, String ability) => user.admin ? true : null);
      expect(await Gate.allows(User(9, admin: true), 'update', post), isTrue);
    });

    test('Policy.before runs before its methods', () async {
      Gate.policy<Post>(AdminPostPolicy());
      expect(await Gate.allows(User(9, admin: true), 'update', post), isTrue);
      expect(await Gate.allows(User(9), 'update', post), isFalse);
    });

    test('a method with a wrong signature fails at Gate.policy', () {
      expect(() => Gate.policy<Post>(BadPolicy()), throwsArgumentError);
    });
  });
}

class AdminPostPolicy extends PostPolicy {
  @override
  bool? before(User user, String ability) => user.admin ? true : null;
}
