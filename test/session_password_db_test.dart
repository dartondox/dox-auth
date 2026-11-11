// ignore_for_file: depend_on_referenced_packages
import 'dart:io';

import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart' hide Schema;
import 'package:dox_core/testing.dart';
import 'package:dox_orm/dox_orm.dart';
import 'package:test/test.dart';

import 'jwt_auth_test.dart' show secret;
import 'session_auth_test.dart' show Browser;

/// A real dox_orm model on SQLite, written by hand like a generated one.
class DbUser extends Model<DbUser> {
  int? get id => tempIdValue as int?;
  set id(int? value) => tempIdValue = value;

  String? email;
  String? password;

  DbUser() {
    hidden = <String>['password'];
  }

  @override
  String get tableName => 'session_db_users';

  @override
  Map<String, dynamic> get timestampsColumn => const <String, dynamic>{
    'created_at': null,
    'updated_at': null,
  };

  @override
  List<String> get tableColumns => const <String>['id', 'email', 'password'];

  @override
  DbUser fromMap(Map<String, dynamic> m) => DbUser()
    ..id = m['id'] as int?
    ..email = m['email'] as String?
    ..password = m['password'] as String?;

  @override
  Map<String, dynamic> columnsToMap() => <String, dynamic>{
    'id': id,
    'email': email,
    'password': password,
  };

  @override
  Map<String, dynamic> convertToMap(dynamic i) => columnsToMap();

  @override
  bool setColumnValue(String column, dynamic value) {
    if (column != 'password' || value is! String?) return false;
    password = value;
    return true;
  }
}

class DbRouter extends Router {
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
    Route.get('me', <dynamic>[
      AuthMiddleware(),
      (DoxRequest req) => req.auth?.user<DbUser>()?.email,
    ]);
    Route.post('logout-others', <dynamic>[
      AuthMiddleware(),
      (DoxRequest req) async {
        await (req.auth as Auth).logoutOtherDevices(req, 'secret');
        return 'done';
      },
    ]);
    Route.post('change-password', <dynamic>[
      AuthMiddleware(),
      (DoxRequest req) async {
        DbUser user = req.auth!.user<DbUser>()!;
        user.password = Hash.make('new', rounds: 4);
        await user.save();
        Auth().updateSessionPasswordHash(req, user);
        return 'changed';
      },
    ]);
  }
}

void main() {
  late DoxTestClient client;
  // a file, not :memory:, so every connection sees the same table
  Directory dir = Directory.systemTemp.createTempSync('dox_auth_db_');

  setUpAll(() async {
    SqlQueryBuilder.initializeWithDatabaseConfig(
      DatabaseConfig(
        connection: 'sqlite',
        connections: <String, ConnectionConfig>{
          'sqlite': ConnectionConfig(
            driver: Driver.sqlite,
            database: '${dir.path}/test.db',
            debug: false,
          ),
        },
      ),
    );
    await SqlQueryBuilder()
        .getDBDriver('sqlite')
        .query(
          'CREATE TABLE session_db_users '
          '(id INTEGER PRIMARY KEY, email TEXT, password TEXT)',
        );
    Auth.initialize(
      AuthConfig(
        defaultGuard: 'web',
        guards: <String, AuthGuard>{
          'web': AuthGuard(
            driver: SessionAuthDriver(hashRounds: 4),
            provider: AuthProvider(model: () => DbUser()),
          ),
        },
        flags: const AuthFlags(endSessionsOnPasswordChange: true),
      ),
    );
    client = await DoxTestClient.start(
      AppConfig(
        appKey: secret,
        routers: <Router>[DbRouter()],
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
    dir.deleteSync(recursive: true);
  });

  setUp(() async {
    String hash = Hash.make('secret', rounds: 4);
    await SqlQueryBuilder()
        .getDBDriver('sqlite')
        .query('DELETE FROM session_db_users');
    await SqlQueryBuilder()
        .getDBDriver('sqlite')
        .query(
          'INSERT INTO session_db_users (id, email, password) VALUES '
          "(1, 'db@dox.dev', '$hash')",
        );
  });

  Future<Browser> loggedIn() async {
    Browser browser = Browser(client);
    TestResponse res = await browser.post('/login', <String, String>{
      'email': 'db@dox.dev',
      'password': 'secret',
    });
    expect(res.body, 'in');
    return browser;
  }

  test('logoutOtherDevices keeps this session on the next request', () async {
    Browser phone = await loggedIn();
    Browser laptop = await loggedIn();
    expect((await laptop.post('/logout-others')).body, 'done');
    expect((await laptop.get('/me')).body, 'db@dox.dev');
    expect((await laptop.get('/me')).body, 'db@dox.dev');
    expect((await phone.get('/me')).status, 401);
  });

  test('updateSessionPasswordHash keeps this session after save()', () async {
    Browser phone = await loggedIn();
    Browser laptop = await loggedIn();
    expect((await laptop.post('/change-password')).body, 'changed');
    expect((await laptop.get('/me')).body, 'db@dox.dev');
    expect((await laptop.get('/me')).body, 'db@dox.dev');
    expect((await phone.get('/me')).status, 401);
  });
}
