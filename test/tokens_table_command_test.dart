import 'dart:async';
import 'dart:io';

import 'package:dox_auth/commands.dart';
import 'package:dox_core/command.dart';
import 'package:test/test.dart';

void main() {
  late Directory folder;

  setUp(() {
    folder = Directory.systemTemp.createTempSync('dox_auth_tokens_table_');
  });

  tearDown(() {
    exitCode = 0;
    folder.deleteSync(recursive: true);
  });

  List<File> files() => folder.listSync().whereType<File>().toList();

  test('commands has auth:tokens-table', () {
    expect(commands.map((Command c) => c.name), contains('auth:tokens-table'));
  });

  test('writes the migration once', () async {
    TokensTableCommand command = TokensTableCommand(
      migrations: MigrationFile(folder: folder),
    );
    await command.run(<String>[]);
    expect(files(), hasLength(1));
    expect(files().first.path, endsWith('_create_access_tokens_table.dart'));
    expect(
      files().first.readAsStringSync(),
      contains('AccessTokenTables.up(schema);'),
    );
    expect(exitCode, 0);

    await command.run(<String>[]);
    expect(files(), hasLength(1));
    expect(exitCode, 1);
  });

  test('flags set the options of AccessTokenTables.up', () async {
    await TokensTableCommand(migrations: MigrationFile(folder: folder))
        .run(<String>['--uuid', '--users-table=users', '--users-key=uid']);
    expect(exitCode, 0);
    expect(
      files().first.readAsStringSync(),
      contains(
        "AccessTokenTables.up(schema, uuidIds: true, usersTable: 'users', "
        "usersKey: 'uid');",
      ),
    );
  });

  test('a bad flag writes nothing', () async {
    for (List<String> args in <List<String>>[
      <String>['--nope'],
      <String>['--users-table=users; drop'],
      <String>['--uuid', '--string-ids'],
      <String>['--uuid', '--uuid'],
      <String>['--users-table=users', '--users-table=admins'],
    ]) {
      exitCode = 0;
      await TokensTableCommand(migrations: MigrationFile(folder: folder))
          .run(args);
      expect(exitCode, 1, reason: '$args');
      expect(files(), isEmpty, reason: '$args');
    }
  });

  test('--string-ids alone', () async {
    await TokensTableCommand(migrations: MigrationFile(folder: folder))
        .run(<String>['--string-ids']);
    expect(exitCode, 0);
    expect(
      files().first.readAsStringSync(),
      contains('AccessTokenTables.up(schema, stringIds: true);'),
    );
  });

  test('--users-key without --users-table warns', () async {
    List<String> lines = <String>[];
    await runZoned(
      () =>
          TokensTableCommand(migrations: MigrationFile(folder: folder))
              .run(<String>['--users-key=uid']),
      zoneSpecification: ZoneSpecification(
        print: (Zone self, ZoneDelegate parent, Zone zone, String line) {
          lines.add(line);
        },
      ),
    );
    expect(exitCode, 0);
    expect(lines, contains(contains('--users-key does nothing')));
    expect(
      files().first.readAsStringSync(),
      contains('AccessTokenTables.up(schema);'),
    );
  });
}
