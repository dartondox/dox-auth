/// The `dox` commands of dox_auth. The `dox` CLI finds this library from
/// the `dox: commands:` key in pubspec.yaml.
library;

import 'package:dox_core/command.dart';

import 'src/commands/tokens_table_command.dart';

export 'src/commands/tokens_table_command.dart';

/// every command of this package
final List<Command> commands = <Command>[TokensTableCommand()];
