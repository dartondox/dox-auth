// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart' hide Schema;
import 'package:dox_orm/dox_orm.dart';
import 'package:test/test.dart';

import 'access_token_auth_test.dart' show dbConfig, env;
import 'jwt_auth_test.dart' show secret;

const String usersTable = 'test_login_field_users';

/// A user with a text `email` and a number `phone`, on a real database.
class PhoneUser extends Model<PhoneUser> {
  int? get id => tempIdValue as int?;
  set id(int? value) => tempIdValue = value;

  String? email;
  int? phone;
  String? password;

  @override
  String get tableName => usersTable;

  @override
  Map<String, dynamic> get timestampsColumn => const <String, dynamic>{
    'created_at': null,
    'updated_at': null,
  };

  @override
  List<String> get tableColumns => const <String>[
    'id',
    'email',
    'phone',
    'password',
  ];

  @override
  PhoneUser fromMap(Map<String, dynamic> m) => PhoneUser()
    ..id = m['id'] as int?
    ..email = m['email'] as String?
    ..phone = m['phone'] == null ? null : int.parse('${m['phone']}')
    ..password = m['password'] as String?;

  @override
  Map<String, dynamic> columnsToMap() => <String, dynamic>{
    'id': id,
    'email': email,
    'phone': phone,
    'password': password,
  };

  @override
  Map<String, dynamic> convertToMap(dynamic i) => columnsToMap();
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
  setUpAll(() async {
    Schema schema = Schema(SqlQueryBuilder().getDBDriver(connection));
    await schema.dropIfExists(usersTable);
    await schema.create(usersTable, (Table t) {
      t.id();
      t.string('email');
      t.bigInteger('phone');
      t.string('password');
    });
    String hash = Hash.make('secret', rounds: 4);
    await SqlQueryBuilder()
        .getDBDriver(connection)
        .execute(
          'INSERT INTO $usersTable (email, phone, password) VALUES '
          "('alice@dox.dev', 123, '$hash'), ('bob@dox.dev', 456, '$hash')",
        );
    Auth.initialize(
      AuthConfig(
        defaultGuard: 'web',
        guards: <String, AuthGuard>{
          'web': AuthGuard(
            driver: JwtAuthDriver(secret: SecretKey(secret), hashRounds: 4),
            provider: AuthProvider(
              model: () => PhoneUser()..withConnection(connection),
              identifierFields: const <String>['email', 'phone'],
            ),
          ),
        },
      ),
    );
  });

  tearDownAll(() async {
    await Schema(SqlQueryBuilder().getDBDriver(connection))
        .dropIfExists(usersTable);
  });

  test('a number in a text field does not log in', () async {
    for (num value in <num>[0, 0.0, 1]) {
      String? token = await Auth().attempt(<String, dynamic>{
        'email': value,
        'password': 'secret',
      });
      expect(token, isNull, reason: 'email: $value');
    }
  });

  test('a normal email login still works', () async {
    String? token = await Auth().attempt(<String, dynamic>{
      'email': 'bob@dox.dev',
      'password': 'secret',
    });
    expect(token, isNotNull);
  });

  test('a login by a number column works with a number or a string', () async {
    for (Object value in <Object>[456, '456']) {
      String? token = await Auth().attempt(<String, dynamic>{
        'phone': value,
        'password': 'secret',
      });
      expect(token, isNotNull, reason: 'phone: $value');
    }
    String? wrong = await Auth().attempt(<String, dynamic>{
      'phone': 999,
      'password': 'secret',
    });
    expect(wrong, isNull);
  });

  test('a value that does not fit a number column fails the login', () async {
    for (Object value in <Object>['abc', 456.5, 1e21]) {
      String? token = await Auth().attempt(<String, dynamic>{
        'phone': value,
        'password': 'secret',
      });
      expect(token, isNull, reason: 'phone: $value');
    }
  });

  test('a bad value in a transaction does not break the transaction', () async {
    await QueryBuilder.transaction<void>(() async {
      String? token = await Auth().attempt(<String, dynamic>{
        'phone': 'abc',
        'password': 'secret',
      });
      expect(token, isNull);

      /// the next query in the same transaction still works
      String? good = await Auth().attempt(<String, dynamic>{
        'phone': 456,
        'password': 'secret',
      });
      expect(good, isNotNull);
    }, connection: connection);
  });
}
