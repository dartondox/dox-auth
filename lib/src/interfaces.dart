import 'dart:io';

import 'package:dox_auth/src/auth_engine.dart';
import 'package:dox_core/dox_core.dart' show Dox;
import 'package:dox_core/utils/hash.dart';
import 'package:dox_orm/dox_orm.dart';

class AuthGuard {
  final AuthDriver driver;
  final AuthProvider provider;

  const AuthGuard({required this.driver, required this.provider});
}

class AuthProvider {
  final dynamic Function() model;

  final List<String> identifierFields;
  final String passwordField;

  const AuthProvider({
    required this.model,
    this.identifierFields = const <String>['email'],
    this.passwordField = 'password',
  });
}

class AuthConfig {
  final String defaultGuard;
  final Map<String, AuthGuard> guards;

  /// Opt-in behaviors, like in Laravel. All are off by default.
  /// ```
  /// AuthConfig(defaultGuard: 'web', guards: guards, flags: AuthFlags.all());
  /// ```
  final AuthFlags flags;

  AuthConfig({
    required this.defaultGuard,
    this.guards = const <String, AuthGuard>{},
    this.flags = const AuthFlags(),
  });
}

/// Opt-in behaviors of dox_auth. Each one works like Laravel. All are
/// off by default. `AuthFlags.all()` turns all of them on.
/// ```
/// AuthFlags(forbidGuest: true)
/// ```
class AuthFlags {
  /// `req.authorize()` and `Can` give a guest 403, not 401. The 403
  /// has the message of the gate, like for a user who may not do it.
  // NEXT MAJOR: make this the default, then remove the flag.
  final bool forbidGuest;

  /// `AuthMiddleware(redirectTo: ...)` gives a JSON or XHR client a
  /// 401, not a redirect. A JSON client sends an `Accept` header with
  /// json, a JSON body, or `X-Requested-With: XMLHttpRequest`. An
  /// Inertia request still gets the redirect.
  // NEXT MAJOR: make this the default, then remove the flag.
  final bool jsonNoRedirect;

  const AuthFlags({this.forbidGuest = false, this.jsonNoRedirect = false});

  /// All flags on.
  const AuthFlags.all() : forbidGuest = true, jsonNoRedirect = true;
}

/// A driver checks tokens and logins for a guard.
/// [guard] is the name of the guard in `AuthConfig.guards`.
/// Use `AuthEngine().guard(guard).provider` to get its user provider.
abstract class AuthDriver {
  Future<Model<dynamic>?> verifyToken(IDoxRequest req, String guard);

  Future<Model<dynamic>?> attempt(
    Map<String, dynamic> credentials,
    String guard,
  );

  /// A token for the user. `Auth` passes `user.toJson()`, like in 3.0.2.
  /// When the primary key is hidden, the id is added as `sub`.
  String? createToken(Map<String, dynamic>? userPayload, String guard);

  /// Sends [error] to `AppConfig.exceptionHandler`, so it shows up in
  /// the log or the error tracker of the app. Before Dox is set up, it
  /// goes to stderr. For an error while a token is checked.
  static void reportError(Object error, StackTrace stackTrace) {
    try {
      Dox().config.exceptionHandler.report(error, stackTrace);
    } catch (_) {
      stderr.writeln('[dox] dox_auth verifyToken failed: $error');
      stderr.writeln(stackTrace);
    }
  }

  /// checked when no user is found, so a login takes as long for an
  /// unknown email as for a wrong password. One per bcrypt cost.
  static final Map<int, Future<String>> _dummyHashes = <int, Future<String>>{};

  /// Make the dummy hash of [rounds] now, in another isolate, so the
  /// first login does not pay for it. A bad cost fails on the first
  /// login, not here.
  static void prepareDummyHash(int rounds) {
    _dummyHashes.putIfAbsent(rounds, () {
      return Hash.makeAsync('dox-no-user', rounds: rounds)..ignore();
    });
  }

  /// The user of [credentials] when the password matches, else null.
  /// [rounds] is the bcrypt cost of the stored hashes.
  static Future<Model<dynamic>?> checkCredentials(
    Map<String, dynamic> credentials,
    String guard,
    int rounds,
  ) async {
    AuthProvider provider = AuthEngine().guard(guard).provider;

    /// password must be a string, otherwise login fails
    dynamic password = credentials[provider.passwordField];
    if (password is! String) {
      return null;
    }

    /// setup new model from auth config
    Model<dynamic> model = provider.model();

    /// setup model query
    Model<dynamic> query = model.debug(model.shouldDebug);

    /// find with credential except password field
    /// since password field is encrypted, we do not need to include
    /// only a string or a number goes into the query. A map or a list
    /// from the request body (like `{"email": {"op": "..."}}`) fails the
    /// login, so the client can not change the query.
    bool hasIdentifier = false;
    for (MapEntry<String, dynamic> entry in credentials.entries) {
      String key = entry.key;
      dynamic value = entry.value;
      if (key == provider.passwordField ||
          !provider.identifierFields.contains(key) ||
          value == null) {
        continue;
      }
      if (value is! String && value is! num) return null;
      query.where(key, value);
      hasIdentifier = true;
    }

    /// without an identifier the query would match any user
    if (!hasIdentifier) {
      return null;
    }

    /// get first record
    Model<dynamic>? userData = await query.getFirst();

    /// the stored hash. null when there is no user or no password.
    dynamic hashed = userData?.toMap(original: true)[provider.passwordField];
    bool hasHash = hashed is String;

    /// always run bcrypt, also when there is no user or no password,
    /// so the answer time does not tell whether the account exists
    /// bcrypt runs in another isolate, so other requests are not blocked
    prepareDummyHash(rounds);
    bool matches = await Hash.verifyAsync(
      password,
      hasHash ? hashed : await _dummyHashes[rounds]!,
    );
    if (userData != null && hasHash && matches) {
      return userData;
    }
    return null;
  }
}
