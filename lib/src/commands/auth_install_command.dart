import 'dart:io';

import 'package:dox_annotation/install.dart';
import 'package:dox_core/command.dart';

import 'tokens_table_command.dart';

/// `dox auth:install`. `dox add auth` runs it. It sets up auth with access
/// tokens in an app that has the ORM: the config with an `api` guard, the
/// provider and the access tokens table migration.
/// It never overwrites a file, so it is safe to run twice.
class AuthInstallCommand extends Command {
  /// [root] is the app folder (the current folder by default). [runner]
  /// runs `dart`, tests pass a fake one.
  AuthInstallCommand({this.root, this.runner});

  final Directory? root;
  final ProcessRunner? runner;

  /// the model that the config uses, the same file as the app template
  static const String userModel = 'lib/app/models/user/user.model.dart';

  @override
  String get name => 'auth:install';

  @override
  String get description => 'Set up auth with access tokens in this app';

  @override
  String get usage => 'auth:install';

  @override
  Future<void> run(List<String> args) async {
    if (args.isNotEmpty) {
      print('Unknown option "${args.first}". Usage: dox $usage');
      exitCode = 1;
      return;
    }
    Installer installer = Installer(root: root, runner: runner);
    String app = installer.appName;

    if (!installer.hasDependency('dox_orm') ||
        !installer.hasDependency('dox_migration')) {
      print('dox_auth needs the ORM. Run `dox add orm` first.');
      exitCode = 1;
      return;
    }
    if (!File('${installer.root.path}/$userModel').existsSync()) {
      print(
        'There is no $userModel. Make the model first: '
        '`dox make:model User -m`. If your User model is elsewhere, write '
        'lib/config/auth.dart by hand (see the authentication docs).',
      );
      exitCode = 1;
      return;
    }

    /// an app with its own config is set up already: change nothing else
    bool hasConfig = File('${installer.root.path}/lib/config/auth.dart')
        .existsSync();

    await installer.addDependency('dox_auth');
    await installer.addDependency('dox_builder', dev: true);
    await installer.addDependency('build_runner', dev: true);

    if (hasConfig) {
      installer.note('skipped  lib/config/auth.dart (already there)');
      installer.note('skipped  provider and tokens migration');
      installer.printSummary(<String>[
        'lib/config/auth.dart is already there, so the provider and the '
            'tokens migration were not added. Add them by hand if you need '
            'them: `dox auth:tokens-table` makes the migration. See the '
            'authentication docs.',
      ]);
      return;
    }
    installer.writeFile('lib/config/auth.dart', authConfig(app));
    installer.writeFile('lib/providers/auth_provider.dart', authProvider(app));
    _addTokensMigration(installer);

    await installer.buildRunner();
    installer.printSummary(<String>[
      'Make the tokens table: `dox migrate`.',
      'Add the login routes and a controller, see the authentication docs: '
          'https://dartondox.dev/latest/security/authentication/',
    ]);
  }

  /// the same migration as `dox auth:tokens-table --users-table=users`
  void _addTokensMigration(Installer installer) {
    String name = 'create_access_tokens_table';
    MigrationFile migrations = MigrationFile(
      folder: Directory('${installer.root.path}/db/migration'),
    );
    String? path = migrations.create(
      name,
      TokensTableCommand.source(<String>["usersTable: 'users'"]),
    );
    installer.note(
      path == null
          ? 'skipped  $name migration (already there)'
          : 'created  db/migration/${File(path).uri.pathSegments.last}',
    );
  }

  /// `lib/config/auth.dart`: one `api` guard with access tokens
  static String authConfig(String app) {
    return '''
import 'package:dox_auth/dox_auth.dart';
import 'package:$app/app/models/user/user.model.dart';

/// Auth guards
/// -------------------------------
/// A guard is a named way to log in. `Auth()` and `AuthMiddleware()` use
/// `defaultGuard`. This guard keeps the login in an access token that you
/// can revoke. Users are the `User` model.
AuthConfig authConfig = AuthConfig(
  defaultGuard: 'api',
  guards: <String, AuthGuard>{
    'api': AuthGuard(
      driver: AccessTokenAuthDriver(expiresIn: const Duration(days: 30)),
      provider: AuthProvider(model: () => User()),
    ),
  },
);
''';
  }

  /// `lib/providers/auth_provider.dart`: gives the config to dox_auth
  static String authProvider(String app) {
    return '''
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:$app/config/auth.dart';

/// Auth provider
/// --------------------------
/// Gives the config of lib/config/auth.dart to dox_auth at startup.
/// If this project does not need auth, delete this file
/// (Dox finds every DoxProvider class, see lib/generated/container.g.dart).
class AppAuthProvider extends DoxProvider {
  @override
  void setup() {
    Auth.initialize(authConfig);
  }
}
''';
  }
}
