// ignore_for_file: depend_on_referenced_packages
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' show sha256;
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart' hide Schema;
import 'package:dox_orm/dox_orm.dart';
import 'package:test/test.dart';

import 'jwt_auth_test.dart'
    show
        FakeAdmin,
        FakeRequest,
        FakeUser,
        RecordingExceptionHandler,
        admins,
        bearer,
        secret,
        users;

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

/// `stringIds: true`
const String textTable = 'test_access_tokens_text';

/// `usersKey:` with a foreign key to `uid` of [keyUsersTable]
const String keyTable = 'test_access_tokens_key';
const String keyUsersTable = 'test_at_key_users';

/// `uuidIds:` with a foreign key to [uuidUsersTable]
const String uuidTable = 'test_access_tokens_uuid';
const String uuidUsersTable = 'test_at_uuid_users';

/// `usersTable:` with a foreign key to [usersTable]
const String fkTable = 'test_access_tokens_fk';
const String usersTable = 'test_at_users';

/// Its own `verifyToken` that lets no one in.
class ClosedDriver extends AccessTokenAuthDriver {
  ClosedDriver({super.table, super.connection});

  @override
  Future<Model<dynamic>?> verifyToken(IDoxRequest req, String guard) async {
    return null;
  }
}

/// `HttpHeaders.value` throws like this for two `Authorization` headers
class TwoHeaderRequest extends FakeRequest {
  @override
  String? header(String key) {
    throw const HttpException('More than one value for header authorization');
  }
}

/// rows of [sql] as one int, eg. a COUNT(*)
Future<int> count(String connection, String sql) async {
  List<Map<String, dynamic>> rows = await SqlQueryBuilder()
      .getDBDriver(connection)
      .query(sql);
  return int.parse('${rows.single.values.first}');
}

/// Users with a text id, that can hold only digits.
final Map<String, TextUser> textUsers = <String, TextUser>{};

class TextUser extends Model<TextUser> {
  String? id;

  /// the type of the last id given to [find]
  static Type? lastFindType;

  TextUser([this.id]);

  @override
  Map<String, dynamic> convertToMap(dynamic i) => <String, dynamic>{'id': id};

  @override
  Future<TextUser?> find(dynamic arg1, [dynamic arg2]) async {
    lastFindType = arg1.runtimeType;
    if (arg1 is! String) return null;

    /// like MySQL: an exact match first, else any case
    return textUsers[arg1] ??
        textUsers.values
            .where((TextUser u) => u.id!.toLowerCase() == arg1.toLowerCase())
            .firstOrNull;
  }
}

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
        'api2': AuthGuard(
          driver: driver(null),
          provider: AuthProvider(model: () => FakeUser()),
        ),
        'renamed': AuthGuard(
          driver: AccessTokenAuthDriver(
            table: table,
            connection: connection,
            type: 'api',
          ),
          provider: AuthProvider(model: () => FakeUser()),
        ),
        'text': AuthGuard(
          driver: AccessTokenAuthDriver(
            table: textTable,
            connection: connection,
            stringIds: true,
          ),
          provider: AuthProvider(model: () => TextUser()),
        ),
        'uuid': AuthGuard(
          driver: AccessTokenAuthDriver(
            table: uuidTable,
            connection: connection,
            uuidIds: true,
          ),
          provider: AuthProvider(model: () => TextUser()),
        ),
        'key': AuthGuard(
          driver: AccessTokenAuthDriver(
            table: keyTable,
            connection: connection,
          ),
          provider: AuthProvider(model: () => FakeUser()),
        ),
        'fk': AuthGuard(
          driver: AccessTokenAuthDriver(table: fkTable, connection: connection),
          provider: AuthProvider(model: () => FakeUser()),
        ),
        'closed': AuthGuard(
          driver: ClosedDriver(table: table, connection: connection),
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
    await AccessTokenTables.down(schema, table: textTable);
    await AccessTokenTables.up(schema, table: textTable, stringIds: true);
    await AccessTokenTables.down(schema, table: fkTable);
    await schema.dropIfExists(usersTable);
    await schema.create(usersTable, (Table t) => t.id());
    await AccessTokenTables.up(schema, table: fkTable, usersTable: usersTable);
    await AccessTokenTables.down(schema, table: keyTable);
    await schema.dropIfExists(keyUsersTable);
    await schema.create(keyUsersTable, (Table t) => t.id('uid'));
    await AccessTokenTables.up(
      schema,
      table: keyTable,
      usersTable: keyUsersTable,
      usersKey: 'uid',
    );
    await AccessTokenTables.down(schema, table: uuidTable);
    await schema.dropIfExists(uuidUsersTable);
    await schema.create(uuidUsersTable, (Table t) => t.uuid('id').primary());
    await AccessTokenTables.up(
      schema,
      table: uuidTable,
      uuidIds: true,
      usersTable: uuidUsersTable,
    );
  });

  setUp(() async {
    useConnection(connection);
    await SqlQueryBuilder()
        .getDBDriver(connection)
        .execute('DELETE FROM $table');
    await SqlQueryBuilder()
        .getDBDriver(connection)
        .execute('DELETE FROM $textTable');
    users.clear();
    textUsers.clear();
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

  test('a token can expire in 20 years (after 2038)', () async {
    AccessToken token = await Auth().createAccessToken(
      alice,
      expiresIn: const Duration(days: 365 * 20),
    );
    DateTime want = DateTime.now().toUtc().add(const Duration(days: 365 * 20));
    AccessToken listed = (await Auth().accessTokens(alice)).single;
    expect(
      listed.expiresAt!.difference(want).abs(),
      lessThan(const Duration(seconds: 5)),
    );
    expect((await verify(token.value)).isLoggedIn(), isTrue);
  });

  test('a token of one guard fails on a guard with another type', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    AccessToken other = await Auth(guard: 'api2').createAccessToken(alice);
    expect(token.type, 'api');
    expect(other.type, 'api2');
    expect((await verify(token.value)).isLoggedIn(), isTrue);
    expect((await verify(token.value, guard: 'api2')).isLoggedIn(), isFalse);
    expect((await verify(other.value)).isLoggedIn(), isFalse);
    expect((await verify(other.value, guard: 'api2')).isLoggedIn(), isTrue);

    // list and revoke see only the tokens of their own type
    expect(await Auth(guard: 'api2').accessTokens(alice), hasLength(1));
    expect(
      await Auth(guard: 'api2').revokeAccessToken(alice, token.id),
      isFalse,
    );
    expect(await Auth(guard: 'api2').revokeAllAccessTokens(alice), 1);
    expect((await verify(token.value)).isLoggedIn(), isTrue);

    // the type option keeps tokens working under another guard name
    expect((await verify(token.value, guard: 'renamed')).isLoggedIn(), isTrue);
  });

  test('an int id is an int column, plain SQL finds it', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    expect(token.tokenableId, 1);
    expect((await Auth().accessTokens(alice)).single.tokenableId, 1);
    expect(
      await count(
        connection,
        'SELECT COUNT(*) AS c FROM $table WHERE tokenable_id = 1',
      ),
      1,
    );
  });

  test('a text id stays text, plain SQL finds it', () async {
    TextUser user = textUsers['123'] = TextUser('123');
    AccessToken token = await Auth(guard: 'text').createAccessToken(user);
    expect(token.tokenableId, '123');
    Auth auth = await verify(token.value, guard: 'text');
    expect(TextUser.lastFindType, String);
    expect(auth.user<TextUser>()?.id, '123');
    expect(await Auth(guard: 'text').accessTokens(user), hasLength(1));
    expect(
      await count(
        connection,
        "SELECT COUNT(*) AS c FROM $textTable WHERE tokenable_id = '123'",
      ),
      1,
    );
  });

  test('text ids are compared exactly (case)', () async {
    TextUser lower = textUsers['abc'] = TextUser('abc');
    TextUser upper = textUsers['ABC'] = TextUser('ABC');
    AccessToken token = await Auth(guard: 'text').createAccessToken(lower);
    expect(await Auth(guard: 'text').accessTokens(upper), isEmpty);
    expect(
      await Auth(guard: 'text').revokeAccessToken(upper, token.id),
      isFalse,
    );
    expect(await Auth(guard: 'text').revokeAllAccessTokens(upper), 0);
    Auth auth = await verify(token.value, guard: 'text');
    expect(auth.user<TextUser>()?.id, 'abc');
  });

  test(
    'a token of a deleted text id does not log in as another case',
    () async {
      TextUser lower = textUsers['abc'] = TextUser('abc');
      AccessToken token = await Auth(guard: 'text').createAccessToken(lower);
      textUsers.remove('abc');
      textUsers['ABC'] = TextUser('ABC');
      expect((await verify(token.value, guard: 'text')).isLoggedIn(), isFalse);
    },
  );

  test('uuidIds: a uuid column with a foreign key to uuid users', () async {
    DBDriver db = SqlQueryBuilder().getDBDriver(connection);
    const String id = '0b6f3c2e-6a52-4c4e-9d3a-6f1c1e0a7b11';
    await db.execute('DELETE FROM $uuidTable');
    await db.execute('DELETE FROM $uuidUsersTable');
    await db.execute("INSERT INTO $uuidUsersTable (id) VALUES ('$id')");
    TextUser user = textUsers[id] = TextUser(id);
    AccessToken token = await Auth(guard: 'uuid').createAccessToken(user);
    expect(token.tokenableId, id);
    expect((await verify(token.value, guard: 'uuid')).user<TextUser>()?.id, id);
    expect(await Auth(guard: 'uuid').accessTokens(user), hasLength(1));
    await db.execute("DELETE FROM $uuidUsersTable WHERE id = '$id'");
    expect(await count(connection, 'SELECT COUNT(*) AS c FROM $uuidTable'), 0);
  });

  test('uuidIds: a uuid in upper case is kept in lower case', () async {
    DBDriver db = SqlQueryBuilder().getDBDriver(connection);
    const String id = 'AB6F3C2E-6A52-4C4E-9D3A-6F1C1E0A7B11';
    await db.execute('DELETE FROM $uuidTable');
    await db.execute('DELETE FROM $uuidUsersTable');
    // Postgres keeps a uuid in lower case
    await db.execute(
      "INSERT INTO $uuidUsersTable (id) VALUES ('${id.toLowerCase()}')",
    );
    TextUser user = textUsers[id] = TextUser(id);
    AccessToken token = await Auth(guard: 'uuid').createAccessToken(user);
    expect(token.tokenableId, id.toLowerCase());
    expect((await verify(token.value, guard: 'uuid')).isLoggedIn(), isTrue);
    expect(await Auth(guard: 'uuid').accessTokens(user), hasLength(1));
    expect(await Auth(guard: 'uuid').revokeAccessToken(user, token.id), isTrue);
    expect((await verify(token.value, guard: 'uuid')).isLoggedIn(), isFalse);
  });

  test('a user of another model is an error, not a token', () async {
    FakeAdmin admin = admins[1] = FakeAdmin(1, 'root@dox.dev');
    AccessToken own = await Auth().createAccessToken(alice);
    expect(() => Auth().createAccessToken(admin), throwsArgumentError);
    expect(() => Auth().accessTokens(admin), throwsArgumentError);
    expect(() => Auth().revokeAccessToken(admin, own.id), throwsArgumentError);
    expect(() => Auth().revokeAllAccessTokens(admin), throwsArgumentError);
    expect((await verify(own.value)).isLoggedIn(), isTrue);
    expect(await count(connection, 'SELECT COUNT(*) AS c FROM $table'), 1);
  });

  test('two Authorization headers give no user, not an error', () async {
    RecordingExceptionHandler handler = RecordingExceptionHandler();
    Dox().config = AppConfig(appKey: secret, exceptionHandler: handler);
    AccessToken token = await Auth().createAccessToken(alice);
    Auth auth = Auth();
    await auth.verifyToken(TwoHeaderRequest());
    expect(auth.isLoggedIn(), isFalse);
    await Auth().revokeToken(TwoHeaderRequest());
    expect((await verify(token.value)).isLoggedIn(), isTrue);
    expect(handler.errors, isEmpty);
  });

  test('userFromToken checks an access token with no request', () async {
    AccessToken token = await Auth().createAccessToken(
      alice,
      abilities: <String>['chat'],
    );
    Auth auth = Auth();
    expect((await auth.userFromToken<FakeUser>(token.value))?.id, 1);
    expect(auth.currentAccessToken?.id, token.id);
    expect(auth.tokenCan('chat'), isTrue);
    expect(auth.tokenCan('admin'), isFalse);

    expect(await Auth().userFromToken<FakeUser>(null), isNull);
    expect(
      await Auth().userFromToken<FakeUser>('Bearer ${token.value}'),
      isNull,
    );
    expect(await Auth().userFromToken<FakeUser>('${token.value}x'), isNull);
    expect(
      await Auth(guard: 'api2').userFromToken<FakeUser>(token.value),
      isNull,
    );
    await Auth().revokeAccessToken(alice, token.id);
    expect(await Auth().userFromToken<FakeUser>(token.value), isNull);
  });

  test(
    'revokeToken after userFromToken revokes the token of the request',
    () async {
      AccessToken first = await Auth().createAccessToken(alice);
      AccessToken second = await Auth().createAccessToken(alice);
      Auth auth = Auth();
      await auth.userFromToken<FakeUser>(first.value);
      await auth.revokeToken(bearer(second.value));
      expect((await verify(first.value)).isLoggedIn(), isTrue);
      expect((await verify(second.value)).isLoggedIn(), isFalse);
    },
  );

  test('a user id of the wrong type is an error', () async {
    expect(
      () => Auth(guard: 'text').createAccessToken(alice),
      throwsArgumentError,
    );
    expect(() => Auth().createAccessToken(TextUser('1')), throwsArgumentError);
  });

  test('usersTable: deleting the user deletes the tokens', () async {
    DBDriver db = SqlQueryBuilder().getDBDriver(connection);
    await db.execute('DELETE FROM $fkTable');
    await db.execute('DELETE FROM $usersTable');
    await db.execute('INSERT INTO $usersTable (id) VALUES (1)');
    AccessToken token = await Auth(guard: 'fk').createAccessToken(alice);
    expect((await verify(token.value, guard: 'fk')).isLoggedIn(), isTrue);
    await db.execute('DELETE FROM $usersTable WHERE id = 1');
    expect(await count(connection, 'SELECT COUNT(*) AS c FROM $fkTable'), 0);
    expect((await verify(token.value, guard: 'fk')).isLoggedIn(), isFalse);
  });

  test('usersKey: a foreign key to another key name', () async {
    DBDriver db = SqlQueryBuilder().getDBDriver(connection);
    await db.execute('DELETE FROM $keyTable');
    await db.execute('DELETE FROM $keyUsersTable');
    await db.execute('INSERT INTO $keyUsersTable (uid) VALUES (1)');
    AccessToken token = await Auth(guard: 'key').createAccessToken(alice);
    expect((await verify(token.value, guard: 'key')).isLoggedIn(), isTrue);
    await db.execute('DELETE FROM $keyUsersTable WHERE uid = 1');
    expect(await count(connection, 'SELECT COUNT(*) AS c FROM $keyTable'), 0);
  });

  test('a name over 255 characters is an error, not a row', () async {
    expect(
      () => Auth().createAccessToken(alice, name: 'x' * 256),
      throwsArgumentError,
    );
    expect(await count(connection, 'SELECT COUNT(*) AS c FROM $table'), 0);
    AccessToken ok = await Auth().createAccessToken(alice, name: 'x' * 255);
    expect(ok.name, 'x' * 255);
  });

  test('revokeAll deletes many tokens, only of the user', () async {
    for (int i = 0; i < 30; i++) {
      await Auth().createAccessToken(alice);
    }
    AccessToken b1 = await Auth().createAccessToken(bob);
    expect(await Auth().revokeAllAccessTokens(alice), 30);
    expect(await Auth().accessTokens(alice), isEmpty);
    expect((await verify(b1.value)).isLoggedIn(), isTrue);
    expect(await Auth().revokeAllAccessTokens(alice), 0);

    TextUser user = textUsers['u1'] = TextUser('u1');
    TextUser upper = textUsers['U1'] = TextUser('U1');
    for (int i = 0; i < 3; i++) {
      await Auth(guard: 'text').createAccessToken(user);
    }
    AccessToken other = await Auth(guard: 'text').createAccessToken(upper);
    expect(await Auth(guard: 'text').revokeAllAccessTokens(user), 3);
    expect(await Auth(guard: 'text').accessTokens(upper), hasLength(1));
    expect((await verify(other.value, guard: 'text')).isLoggedIn(), isTrue);
  });

  test('pruneExpiredAccessTokens deletes only expired tokens', () async {
    await Auth().createAccessToken(
      alice,
      expiresIn: const Duration(minutes: -1),
    );
    AccessToken live = await Auth().createAccessToken(
      alice,
      expiresIn: const Duration(days: 365 * 20),
    );
    AccessToken forever = await Auth().createAccessToken(alice);
    expect(await Auth().pruneExpiredAccessTokens(), 1);
    expect(
      <int>[for (AccessToken t in await Auth().accessTokens(alice)) t.id],
      <int>[forever.id, live.id],
    );
  });

  test('Auth uses the verifyToken of a driver subclass', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    Auth auth = await verify(token.value, guard: 'closed');
    expect(auth.isLoggedIn(), isFalse);
    expect(auth.currentAccessToken, isNull);
    expect(auth.tokenCan('anything'), isFalse);
  });

  test('revokeToken on the Auth of the request uses its token', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    Auth auth = await verify(token.value);
    // no header now: the token from verifyToken is used
    await auth.revokeToken(FakeRequest());
    expect((await verify(token.value)).isLoggedIn(), isFalse);
  });

  test(
    'a failed last_used_at write does not log the user out',
    skip: connection == 'sqlite' ? null : 'needs a SQLite trigger',
    () async {
      DBDriver db = SqlQueryBuilder().getDBDriver(connection);
      await db.execute(
        'CREATE TRIGGER no_update BEFORE UPDATE ON $table '
        "BEGIN SELECT RAISE(ABORT, 'read only'); END",
      );
      addTearDown(() => db.execute('DROP TRIGGER no_update'));
      AccessToken token = await Auth().createAccessToken(alice);
      Auth auth = await verify(token.value);
      expect(auth.isLoggedIn(), isTrue);
      expect((await Auth().accessTokens(alice)).single.lastUsedAt, isNull);
    },
  );

  test('a revoked token fails', () async {
    AccessToken one = await Auth().createAccessToken(alice);
    AccessToken two = await Auth().createAccessToken(alice);
    expect(await Auth().revokeAccessToken(alice, one.id), isTrue);
    expect((await verify(one.value)).isLoggedIn(), isFalse);
    expect((await verify(two.value)).isLoggedIn(), isTrue);
    expect(await Auth().revokeAccessToken(alice, one.id), isFalse);
  });

  test('optional AuthMiddleware: a revoked token goes on as a guest', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    await Auth().revokeAccessToken(alice, token.id);
    FakeRequest req = bearer(token.value);
    expect(await AuthMiddleware(optional: true).handle(req), same(req));
    expect(req.auth, isNull);
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

  test('once() and attempt() drop the access token of the request', () async {
    AccessToken token = await Auth().createAccessToken(
      alice,
      abilities: <String>['chat'],
    );
    Auth auth = await verify(token.value);
    expect(auth.tokenCan('chat'), isTrue);
    await auth.once(<String, dynamic>{'email': 'bob@dox.dev', 'password': 'b'});
    expect(auth.user<FakeUser>()?.id, 2);
    expect(auth.currentAccessToken, isNull);
    expect(auth.tokenCan('chat'), isFalse);

    auth = await verify(token.value);
    await auth.attempt(<String, dynamic>{
      'email': 'bob@dox.dev',
      'password': 'nope',
    });
    expect(auth.currentAccessToken, isNull);
  });

  test('once() and attempt() drop the token that revokeToken uses', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    Auth auth = await verify(token.value);
    await auth.once(<String, dynamic>{'email': 'bob@dox.dev', 'password': 'b'});
    // no header: the old token of alice must not be revoked
    await auth.revokeToken(FakeRequest());
    expect((await verify(token.value)).isLoggedIn(), isTrue);

    auth = await verify(token.value);
    await auth.attempt(<String, dynamic>{
      'email': 'bob@dox.dev',
      'password': 'b',
    });
    await auth.revokeToken(FakeRequest());
    expect((await verify(token.value)).isLoggedIn(), isTrue);
  });

  test(
    'setUser() and userFromToken() drop the token of another user',
    () async {
      AccessToken token = await Auth().createAccessToken(alice);
      AccessToken other = await Auth().createAccessToken(bob);

      Auth auth = await verify(token.value);
      auth.setUser(FakeRequest(), bob);
      expect(auth.currentAccessToken, isNull);
      // no header: the old token of alice must not be revoked
      await auth.revokeToken(FakeRequest());
      expect((await verify(token.value)).isLoggedIn(), isTrue);

      auth = await verify(token.value);
      await auth.userFromToken<FakeUser>(other.value);
      await auth.revokeToken(FakeRequest());
      expect((await verify(token.value)).isLoggedIn(), isTrue);
    },
  );

  test('setUser() with the same user keeps the token of the request', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    Auth auth = await verify(token.value);
    auth.setUser(FakeRequest(), auth.user<FakeUser>()!);
    expect(auth.currentAccessToken?.id, token.id);
    await auth.revokeToken(FakeRequest());
    expect((await verify(token.value)).isLoggedIn(), isFalse);
  });

  test('setUser() with the same user loaded again keeps the token', () async {
    AccessToken token = await Auth().createAccessToken(alice);
    Auth auth = await verify(token.value);
    auth.setUser(FakeRequest(), FakeUser(1, alice.email, alice.password));
    expect(auth.currentAccessToken?.id, token.id);
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
