import 'dart:io';

import 'package:dox_annotation/install.dart';
import 'package:dox_auth/commands.dart';
import 'package:dox_core/command.dart';
import 'package:test/test.dart';

/// records the `dart` commands, runs nothing
class FakeRunner extends ProcessRunner {
  final List<String> calls = <String>[];

  @override
  Future<int> run(String executable, List<String> args, String folder) async {
    calls.add(args.join(' '));
    return 0;
  }
}

void main() {
  late Directory root;
  late FakeRunner runner;

  setUp(() {
    root = Directory.systemTemp.createTempSync('dox_auth_install_');
    File('${root.path}/pubspec.yaml').writeAsStringSync(
      'name: my_app\n\ndependencies:\n  dox_core: ^3.1.0\n'
      '  dox_orm: ^3.1.0\n  dox_migration: ^3.1.0\n',
    );
    File('${root.path}/lib/app/models/user/user.model.dart')
      ..createSync(recursive: true)
      ..writeAsStringSync('// my model\n');
    runner = FakeRunner();
    exitCode = 0;
  });

  tearDown(() {
    exitCode = 0;
    root.deleteSync(recursive: true);
  });

  String read(String path) => File('${root.path}/$path').readAsStringSync();

  Future<void> install(List<String> args) {
    return AuthInstallCommand(root: root, runner: runner).run(args);
  }

  /// every file of the app and its text
  Map<String, String> snapshot() {
    Map<String, String> files = <String, String>{};
    for (FileSystemEntity f in root.listSync(recursive: true)) {
      if (f is File) files[f.path] = f.readAsStringSync();
    }
    return files;
  }

  test('commands has auth:install', () {
    expect(commands.map((Command c) => c.name), contains('auth:install'));
  });

  test('writes the config, the provider and the tokens migration', () async {
    await install(<String>[]);
    expect(exitCode, 0);
    expect(runner.calls, <String>[
      'pub add dox_auth',
      'pub add --dev dox_builder',
      'pub add --dev build_runner',
      'run build_runner build',
    ]);
    expect(
      read('lib/config/auth.dart'),
      contains("import 'package:my_app/app/models/user/user.model.dart';"),
    );
    expect(
      read('lib/providers/auth_provider.dart'),
      contains('AppAuthProvider'),
    );
    List<String> names = Directory('${root.path}/db/migration')
        .listSync()
        .map((FileSystemEntity f) => f.uri.pathSegments.last)
        .toList();
    expect(names.single, endsWith('_create_access_tokens_table.dart'));
    expect(
      read('db/migration/${names.single}'),
      contains("AccessTokenTables.up(schema, usersTable: 'users')"),
    );
  });

  test('a second run changes nothing', () async {
    await install(<String>[]);
    File('${root.path}/lib/config/auth.dart').writeAsStringSync('mine');
    Map<String, String> before = snapshot();
    await install(<String>[]);
    expect(exitCode, 0);
    expect(snapshot(), before);
  });

  test(
    'without the ORM it stops with exit code 1 and changes nothing',
    () async {
      File('${root.path}/pubspec.yaml').writeAsStringSync(
        'name: my_app\n\ndependencies:\n  dox_core: ^3.1.0\n',
      );
      Map<String, String> before = snapshot();
      await install(<String>[]);
      expect(exitCode, 1);
      expect(runner.calls, isEmpty);
      expect(snapshot(), before);
    },
  );

  test('without the User model it stops with exit code 1', () async {
    File('${root.path}/$userModelPath').deleteSync();
    Map<String, String> before = snapshot();
    await install(<String>[]);
    expect(exitCode, 1);
    expect(runner.calls, isEmpty);
    expect(snapshot(), before);
  });

  test('any option stops with exit code 1 and changes nothing', () async {
    for (List<String> args in <List<String>>[
      <String>['--jwt'],
      <String>['jwt'],
    ]) {
      Map<String, String> before = snapshot();
      await install(args);
      expect(exitCode, 1, reason: '$args');
      expect(runner.calls, isEmpty, reason: '$args');
      expect(snapshot(), before, reason: '$args');
      exitCode = 0;
    }
  });
}

const String userModelPath = AuthInstallCommand.userModel;
