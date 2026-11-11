import 'package:dox_auth/src/interfaces.dart';

class AuthEngine {
  late AuthConfig config;

  /// The flags of [config]. All off before `Auth.initialize`, so `Can`
  /// works the same in an app that only uses gates.
  AuthFlags get flags => _ready ? config.flags : const AuthFlags();

  bool _ready = false;

  /// get an auth guard by name. No name gives the default guard.
  /// ```
  /// AuthEngine().guard('admin');
  /// ```
  AuthGuard guard([String? name]) {
    String key = name ?? config.defaultGuard;
    AuthGuard? found = config.guards[key];
    if (found == null) {
      throw ArgumentError.value(key, 'guard', 'no auth guard with this name');
    }
    return found;
  }

  /// singleton
  static final AuthEngine _singleton = AuthEngine._internal();
  factory AuthEngine() => _singleton;
  AuthEngine._internal();

  void init(AuthConfig authConfig) {
    config = authConfig;
    _ready = true;
  }
}
