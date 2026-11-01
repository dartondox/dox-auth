// ignore_for_file: depend_on_referenced_packages
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' show sha256;
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart' hide Schema;
import 'package:dox_orm/dox_orm.dart';
import 'package:test/test.dart';

import 'jwt_auth_test.dart'
    show FakeAdmin, FakeRequest, FakeUser, admins, bearer, secret, users;

/// SQLite always runs. Postgres and MySQL run when `PG_PORT` and
/// `MYSQL_PORT` are set (see .github/workflows/ci.yaml).
Map<String, String> env = Platform.environment;

DatabaseConfig dbConfig = DatabaseConfig(
  connection: 'sqlite',
  connections: <String, ConnectionConfig>{
    'sqlite': ConnectionConfig(
      driver: Driver.sqlite,
      database: ':memory:',
      debug: false,
    ),
    'postgres': ConnectionConfig(
      driver: Driver.postgres,
      host: '127.0.0.1',
      port: int.parse(env['PG_PORT'] ?? '5432'),
      user: 'postgres',
      password: 'postgres',
      database: 'postgres',
      debug: false,
    ),
    'mysql': ConnectionConfig(
      driver: Driver.mysql,
      host: '127.0.0.1',
      port: int.parse(env['MYSQL_PORT'] ?? '3306'),
      user: 'dox',
      password: 'password',
      database: 'dox-framework',
      debug: false,
    ),
  },
);

const String table = 'test_access_tokens';

void useConnection(String connection) {
  AccessTokenAuthDriver driver(Duration? expiresIn) {
    return AccessTokenAuthDriver(
      table: table,
      connection: connection,
      expiresIn: expiresIn,
      hashRounds: 4,
    );
  }

  Auth.initialize(
    AuthConfig(
      defaultGuard: 'api',
      guards: <String, AuthGuard>{
        'api': AuthGuard(
          driver: driver(null),
          provider: AuthProvider(model: () => FakeUser()),
        ),
        'short': AuthGuard(
          driver: driver(const Duration(hours: 1)),
          provider: AuthProvider(model: () => FakeUser()),
        ),
        'admin': AuthGuard(
          driver: driver(null),
          provider: AuthProvider(model: () => FakeAdmin()),
        ),
      },
    ),
  );
}

/// the user of [token], checked like a request does
Future<Auth> verify(String? token, {String? guard}) async {
  Auth auth = Auth(guard: guard);
  await auth.verifyToken(token == null ? FakeRequest() : bearer(token));
  return auth;
}

void main() {
  setUpAll(() {
    Dox().initialize(AppConfig(appKey: secret, totalIsolate: 1));
    SqlQueryBuilder.initializeWithDatabaseConfig(dbConfig);
  });

  for (String connection in <String>['sqlite', 'postgres', 'mysql']) {
    String? skip = switch (connection) {
      'postgres' when env['PG_PORT'] == null => 'no PG_PORT',
      'mysql' when env['MYSQL_PORT'] == null => 'no MYSQL_PORT',
      _ => null,
    };
    group(connection, skip: skip, () => tests(connection));
  }
}

void tests(String connection) {
  late FakeUser alice;
  late FakeUser bob;

  setUpAll(() async {
    Schema schema = Schema(SqlQueryBuilder().getDBDriver(connection));
    await AccessTokenTables.down(schema, table: table);
    await AccessTokenTables.up(schema, table: table);
  });

  setUp(() async {
    useConnection(connection);
    await SqlQueryBuilder()
        .getDBDriver(connection)
        .execute('DELETE FROM $table');
    users.clear();
    admins.clear();
    alice = users[1] = FakeUser(1, 'alice@dox.dev', Hash.make('a', rounds: 4));
    bob = users[2] = FakeUser(2, 'bob@dox.dev', Hash.make('b', rounds: 4));
  });

  test('a new token logs in, and only its hash is kept', () async {
    AccessToken token = await Auth().createAccessToken(alice, name: 'cli');
    String value = token.value!;
    expect(value, matches(RegExp(r'^oat_\d+\.[A-Za-z0-9_-]{43}$')));
    expect(value, startsWith('oat_${token.id}.'));

    List<Map<String, dynamic>> rows = await SqlQueryBuilder()
        .getDBDriver(connection)
        .query('SELECT hash FROM $table');
    String plain = value.split('.').last;
    expect(
      '${rows.single['hash']}',
      sha256.convert(utf8.encode(plain)).toString(),
    );
    expect('${rows.single['hash']}', isNot(contains(plain)));

    Auth auth = await verify(value);
    expect(auth.user<FakeUser>()?.email, 'alice@dox.dev');
    expect(auth.currentAccessToken?.id, token.id);
    expect(auth.currentAccessToken?.name, 'cli');
    expect(auth.currentAccessToken?.value, isNull);
  });

  test('the check sets last_used_at', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    expect(token.lastUsedAt, isNull);
    await verify(token.value);
    List<AccessToken> all = await Auth().accessTokens(alice);
    expect(all.single.lastUsedAt, isNotNull);
    expect(
      all.single.lastUsedAt!.difference(DateTime.now().toUtc()).abs(),
      lessThan(const Duration(seconds: 5)),
    );
  });

  test('an expired token fails', () async {
    AccessToken token = await Auth().createAccessToken(
      alice,
      expiresIn: const Duration(minutes: -1),
    );
    expect((await verify(token.value)).isLoggedIn(), isFalse);
    expect(await Auth().accessTokens(alice), hasLength(1));
  });

  test('expires_at is read back in UTC', () async {
    AccessToken token = await Auth(guard: 'short').createAccessToken(alice);
    DateTime want = DateTime.now().toUtc().add(const Duration(hours: 1));
    expect(
      token.expiresAt!.difference(want).abs(),
      lessThan(const Duration(seconds: 5)),
    );
    AccessToken listed = (await Auth(guard: 'short').accessTokens(alice))
        .single;
    expect(
      listed.expiresAt!.difference(want).abs(),
      lessThan(const Duration(seconds: 5)),
    );
    expect((await verify(token.value, guard: 'short')).isLoggedIn(), isTrue);
  });

  test('a revoked token fails', () async {
    AccessToken one = await Auth().createAccessToken(alice);
    AccessToken two = await Auth().createAccessToken(alice);
    expect(await Auth().revokeAccessToken(alice, one.id), isTrue);
    expect((await verify(one.value)).isLoggedIn(), isFalse);
    expect((await verify(two.value)).isLoggedIn(), isTrue);
    expect(await Auth().revokeAccessToken(alice, one.id), isFalse);
  });

  test('revokeAllAccessTokens stops all tokens of the user only', () async {
    AccessToken a1 = await Auth().createAccessToken(alice);
    AccessToken a2 = await Auth().createAccessToken(alice);
    AccessToken b1 = await Auth().createAccessToken(bob);
    expect(await Auth().revokeAllAccessTokens(alice), 2);
    expect((await verify(a1.value)).isLoggedIn(), isFalse);
    expect((await verify(a2.value)).isLoggedIn(), isFalse);
    expect((await verify(b1.value)).isLoggedIn(), isTrue);
  });

  test('a user can not revoke the token of another user', () async {
    AccessToken b1 = await Auth().createAccessToken(bob);
    expect(await Auth().revokeAccessToken(alice, b1.id), isFalse);
    expect((await verify(b1.value)).isLoggedIn(), isTrue);
  });

  test('revokeToken(req) logs out the token of the request', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    AccessToken other = await Auth().createAccessToken(alice);
    await Auth().revokeToken(bearer(token.value));
    expect((await verify(token.value)).isLoggedIn(), isFalse);
    expect((await verify(other.value)).isLoggedIn(), isTrue);
    await Auth().revokeToken(FakeRequest());
  });

  test('a wrong secret fails', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    String value = token.value!;
    String last = value.substring(value.length - 1);
    String wrong =
        value.substring(0, value.length - 1) + (last == 'A' ? 'B' : 'A');
    expect((await verify(wrong)).isLoggedIn(), isFalse);
  });

  test(
    'the secret of one token does not work with the id of another',
    () async {
      AccessToken a1 = await Auth().createAccessToken(alice);
      AccessToken b1 = await Auth().createAccessToken(bob);
      String mixed = 'oat_${a1.id}.${b1.value!.split('.').last}';
      expect((await verify(mixed)).isLoggedIn(), isFalse);
      String mixed2 = 'oat_${b1.id}.${a1.value!.split('.').last}';
      expect((await verify(mixed2)).isLoggedIn(), isFalse);
    },
  );

  test('a bad format fails', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    String value = token.value!;
    String plain = value.split('.').last;
    for (String bad in <String>[
      '',
      'oat_',
      'oat_${token.id}',
      'oat_${token.id}.',
      'oat_${token.id}.$plain.x',
      'oat_${token.id}.${plain}x',
      'oat_0${token.id}.$plain',
      'oat_-1.$plain',
      'oat_ ${token.id}.$plain',
      'xat_${token.id}.$plain',
      plain,
      'oat_99999999999999999999.$plain',
      "oat_1' OR '1'='1.$plain",
      '$value\n',
      'eyJhbGciOiJIUzI1NiJ9.e30.x',
    ]) {
      expect((await verify(bad)).isLoggedIn(), isFalse, reason: bad);
      expect(await AccessTokenAuthDriver().check(bad, 'api'), isNull);
    }
    expect((await verify(null)).isLoggedIn(), isFalse);
    expect((await verify(value)).isLoggedIn(), isTrue);
  });

  test(
    'a token of one guard fails on a guard with another user table',
    () async {
      admins[1] = FakeAdmin(1, 'root@dox.dev');
      expect(FakeAdmin().tableName, isNot(FakeUser().tableName));
      AccessToken token = await Auth(guard: 'admin')
          .createAccessToken(admins[1]!);
      expect((await verify(token.value, guard: 'admin')).isLoggedIn(), isTrue);
      expect((await verify(token.value)).isLoggedIn(), isFalse);
    },
  );

  test('a token of a deleted user fails', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    users.remove(1);
    expect((await verify(token.value)).isLoggedIn(), isFalse);
  });

  test('tokenCan checks the abilities', () async {
    AccessToken all = await Auth().createAccessToken(alice);
    AccessToken some = await Auth().createAccessToken(
      alice,
      abilities: <String>['posts:read'],
    );
    AccessToken none = await Auth().createAccessToken(
      alice,
      abilities: <String>[],
    );

    Auth allAuth = await verify(all.value);
    expect(allAuth.tokenCan('posts:write'), isTrue);

    Auth someAuth = await verify(some.value);
    expect(someAuth.tokenCan('posts:read'), isTrue);
    expect(someAuth.tokenCan('posts:write'), isFalse);
    expect(someAuth.tokenCan('*'), isFalse);
    expect(someAuth.currentAccessToken!.cannot('posts:write'), isTrue);

    Auth noneAuth = await verify(none.value);
    expect(noneAuth.isLoggedIn(), isTrue);
    expect(noneAuth.tokenCan('posts:read'), isFalse);

    expect((await verify(null)).tokenCan('posts:read'), isFalse);
  });

  test('accessTokens lists newest first, with no hash or value', () async {
    AccessToken one = await Auth().createAccessToken(alice, name: 'one');
    AccessToken two = await Auth().createAccessToken(
      alice,
      name: 'two',
      abilities: <String>['a', 'b'],
    );
    await Auth().createAccessToken(bob);
    List<AccessToken> list = await Auth().accessTokens(alice);
    expect(<int>[for (AccessToken t in list) t.id], <int>[two.id, one.id]);
    expect(list.first.abilities, <String>['a', 'b']);
    expect(list.first.value, isNull);
    Map<String, dynamic> json = list.first.toJson();
    expect(json.keys, isNot(contains('hash')));
    expect(jsonEncode(json), isNot(contains(two.value!.split('.').last)));
  });

  test('attempt gives an access token, a wrong password gives null', () async {
    String? token = await Auth().attempt(<String, dynamic>{
      'email': 'alice@dox.dev',
      'password': 'a',
    });
    expect(token, startsWith('oat_'));
    expect((await verify(token)).user<FakeUser>()?.id, 1);
    expect(
      await Auth().attempt(<String, dynamic>{
        'email': 'alice@dox.dev',
        'password': 'nope',
      }),
      isNull,
    );
  });

  test('login() throws: it can not make a token without the database', () {
    expect(() => Auth().login(alice), throwsStateError);
  });

  test('a missing table fails closed', () async {
    Auth.initialize(
      AuthConfig(
        defaultGuard: 'api',
        guards: <String, AuthGuard>{
          'api': AuthGuard(
            driver: AccessTokenAuthDriver(
              table: 'no_such_table',
              connection: connection,
            ),
            provider: AuthProvider(model: () => FakeUser()),
          ),
        },
      ),
    );
    String fake = 'oat_1.${'A' * 43}';
    expect((await verify(fake)).isLoggedIn(), isFalse);
  });
}
