import 'dart:io';

import 'package:dox_annotation/command.dart';

/// `dox auth:tokens-table`: write a migration that makes the access tokens
/// table (`AccessTokenTables`).
///
/// Flags: `--uuid`, `--string-ids`, `--users-table=<table>` and
/// `--users-key=<column>`. They set the same options of
/// `AccessTokenTables.up`.
class TokensTableCommand extends Command {
  /// [migrations] is `MigrationFile()` (`db/migration`) by default
  TokensTableCommand({MigrationFile? migrations})
    : _migrations = migrations ?? MigrationFile();

  final MigrationFile _migrations;

  /// a table or column name. Nothing else goes into the migration code.
  static final RegExp _identifier = RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$');

  @override
  String get name => 'auth:tokens-table';

  @override
  String get description => 'Create a migration for the access tokens table';

  @override
  String get usage =>
      'auth:tokens-table [--uuid | --string-ids] '
      '[--users-table=<table>] [--users-key=<column>]';

  @override
  Future<void> run(List<String> args) async {
    List<String> options = <String>[];
    Set<String> seen = <String>{};
    bool uuid = false;
    bool stringIds = false;
    String? usersTable;
    String? usersKey;
    for (String arg in args) {
      String flag = arg.split('=').first;
      if (!seen.add(flag)) {
        _fail('$flag is given more than once.');
        return;
      }
      if (arg == '--uuid') {
        uuid = true;
      } else if (arg == '--string-ids') {
        stringIds = true;
      } else if (arg.startsWith('--users-table=')) {
        usersTable = _name(arg, '--users-table=');
        if (usersTable == null) return;
      } else if (arg.startsWith('--users-key=')) {
        usersKey = _name(arg, '--users-key=');
        if (usersKey == null) return;
      } else {
        _fail('Unknown option "$arg". Usage: dox $usage');
        return;
      }
    }
    if (usersTable != null) {
      options.add("usersTable: '$usersTable'");
      if (usersKey != null) options.add("usersKey: '$usersKey'");
    } else if (usersKey != null) {
      print('Warning: --users-key does nothing without --users-table.');
    }
    if (uuid && stringIds) {
      _fail('Use --uuid or --string-ids, not both.');
      return;
    }
    if (uuid) options.insert(0, 'uuidIds: true');
    if (stringIds) options.insert(0, 'stringIds: true');

    String? path = _migrations.create(
      'create_access_tokens_table',
      source(options),
    );
    if (path == null) {
      _fail(
        'A create_access_tokens_table migration is already in db/migration.',
      );
      return;
    }
    String file = File(path).uri.pathSegments.last;
    print('\x1B[32m$file migration created successfully.\x1B[0m');
    if (uuid) print('Set uuidIds: true on AccessTokenAuthDriver too.');
    if (stringIds) print('Set stringIds: true on AccessTokenAuthDriver too.');
    print('Run `dox migrate` to make the table.');
  }

  /// the value of `--flag=value`, or null (and exit code 1) when it is
  /// not a plain table or column name
  String? _name(String arg, String flag) {
    String value = arg.substring(flag.length);
    if (_identifier.hasMatch(value)) return value;
    _fail('$flag needs a table or column name, like ${flag}users.');
    return null;
  }

  void _fail(String message) {
    print(message);
    exitCode = 1;
  }

  /// the migration file. [options] are the named arguments of
  /// `AccessTokenTables.up`, like `uuidIds: true`.
  static String source([List<String> options = const <String>[]]) {
    String args = <String>['schema', ...options].join(', ');
    return '''
// ignore_for_file: file_names
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_migration/dox_migration.dart';

/// The auth_access_tokens table of dox_auth.
class CreateAccessTokensTable extends Migration {
  @override
  Future<void> up(Schema schema) async {
    await AccessTokenTables.up($args);
  }

  @override
  Future<void> down(Schema schema) async {
    await AccessTokenTables.down(schema);
  }
}
''';
  }
}
