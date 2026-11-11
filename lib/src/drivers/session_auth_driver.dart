// ignore_for_file: depend_on_referenced_packages
import 'dart:convert';

import 'package:crypto/crypto.dart' show Hmac, sha256;
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_orm/dox_orm.dart';

/// Keeps the login in the session (`req.session`), for web pages.
/// The browser sends the session cookie, so there is no token.
/// Needs `SessionMiddleware` on the route.
/// ```
/// AuthGuard(driver: SessionAuthDriver(), provider: AuthProvider(...));
///
/// bool ok = await Auth().attemptSession(req, credentials);
/// await Auth().logout(req);
/// ```
class SessionAuthDriver extends AuthDriver {
  /// bcrypt cost of the stored password hashes. Default: 10.
  final int hashRounds;

  SessionAuthDriver({this.hashRounds = 10}) {
    AuthDriver.prepareDummyHash(hashRounds);
  }

  /// The session key of the user id of [guard].
  static String sessionKey(String guard) => 'auth_$guard';

  /// The session key of the password fingerprint of [guard]. See
  /// [storePasswordHash].
  static String passwordHashKey(String guard) => 'auth_${guard}_password_hash';

  /// The label of the key that makes password fingerprints.
  static const String _fingerprintLabel = 'dox:auth-session-password';

  /// An HMAC-SHA256 of the stored password hash of [user], with a key
  /// made from [appKey] (default: `APP_KEY`). The session keeps this, not
  /// the hash itself. A user with no password gets the fingerprint of an
  /// empty text, so setting a password later changes it too.
  static String passwordFingerprint(
    Model<dynamic> user,
    String guard, {
    String? appKey,
  }) {
    String field = AuthEngine().guard(guard).provider.passwordField;
    dynamic hashed = user.toMap(original: true)[field];
    List<int> key = KeyDerivation.derive(
      appKey ?? Dox().config.appKey,
      _fingerprintLabel,
    );
    return Hmac(
      sha256,
      key,
    ).convert(utf8.encode(hashed is String ? hashed : '')).toString();
  }

  /// Keep the password fingerprint of [user] in [session]. With the
  /// `endSessionsOnPasswordChange` flag, a session whose fingerprint
  /// does not match the user any more is logged out.
  void storePasswordHash(Session session, Model<dynamic> user, String guard) {
    session.put(passwordHashKey(guard), passwordFingerprint(user, guard));
  }

  /// true when [stored] is the fingerprint of [user], with `APP_KEY` or
  /// one of `previousKeys`. A match with an old key is stored again with
  /// `APP_KEY`, so a key change does not log users out.
  bool _sameFingerprint(
    Session session,
    String stored,
    Model<dynamic> user,
    String guard,
  ) {
    AppConfig config = Dox().config;
    for (String key in <String>[config.appKey, ...config.previousKeys]) {
      if (Hash.equals(stored, passwordFingerprint(user, guard, appKey: key))) {
        if (key != config.appKey) storePasswordHash(session, user, guard);
        return true;
      }
    }
    return false;
  }

  /// The user of the id in the session, or null.
  @override
  Future<Model<dynamic>?> verifyToken(IDoxRequest req, String guard) async {
    return userFromSession((req as DoxRequest).session, guard);
  }

  /// The user of the id in [session], or null. Same as [verifyToken],
  /// with no request (eg. for a socket).
  Future<Model<dynamic>?> userFromSession(Session session, String guard) async {
    dynamic id = session.get(sessionKey(guard));
    if (id == null) return null;
    Model<dynamic> model = AuthEngine().guard(guard).provider.model();
    Model<dynamic>? user = await model.find(id);
    if (user == null || !AuthEngine().flags.endSessionsOnPasswordChange) {
      return user;
    }
    dynamic stored = session.get(passwordHashKey(guard));
    if (stored is! String) {
      // a session from before this feature: keep it, and start checking it
      storePasswordHash(session, user, guard);
      return user;
    }
    if (!_sameFingerprint(session, stored, user, guard)) {
      // the password changed after this login
      session.invalidate();
      return null;
    }
    return user;
  }

  @override
  Future<Model<dynamic>?> attempt(
    Map<String, dynamic> credentials,
    String guard,
  ) {
    return AuthDriver.checkCredentials(credentials, guard, hashRounds);
  }

  /// There is no token. The session keeps the login.
  @override
  String? createToken(Map<String, dynamic>? userPayload, String guard) => null;

  /// Keep [user] in the session. The session gets a new id, so an id
  /// from before the login is no use (session fixation).
  void login(DoxRequest req, Model<dynamic> user, String guard) {
    Session session = req.session;
    session.regenerate();
    session.put(sessionKey(guard), user.toMap(original: true)[user.primaryKey]);
    storePasswordHash(session, user, guard);
  }

  /// Remove the login and all session data. The session gets a new id.
  void logout(DoxRequest req) => req.session.invalidate();
}
