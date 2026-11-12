// ignore_for_file: depend_on_referenced_packages

import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';

class AuthMiddleware implements IDoxMiddleware {
  /// The guard name from `AuthConfig.guards`.
  /// null uses `AuthConfig.defaultGuard`.
  /// ```
  /// Route.get('/admin', <dynamic>[AuthMiddleware(guard: 'admin'), handler]);
  /// ```
  final String? guard;

  /// Several guard names, tried in order.
  /// The first guard with a good login sets `req.auth`. Do not set
  /// [guard] too.
  /// ```
  /// Route.get('/me', <dynamic>[AuthMiddleware(guards: <String>['web', 'api']), handler]);
  /// ```
  final List<String>? guards;

  /// Send a guest to this page (like `/login`) instead of a 401.
  /// For web pages. null gives the 401. With
  /// `AuthFlags(jsonNoRedirect: true)`, a JSON or XHR client gets the
  /// 401 and no redirect (see `DoxRequest.expectsJson`).
  final String? redirectTo;

  /// Let guests through too. A good login still sets `req.auth`, so
  /// `req.can()` and `req.auth?.user()` work on a public page. A guest,
  /// or a bad, expired or revoked token, goes on with `req.auth` null.
  /// With `JwtAuthDriver` and `AccessTokenAuthDriver`, a database error
  /// also goes on as a guest, but it is reported (see
  /// `AuthDriver.reportError`). With `AccessTokenAuthDriver(throwOnError:
  /// true)` and with `SessionAuthDriver`, a database error is thrown (a
  /// 500 by default). [redirectTo] is not used when this is true.
  /// ```
  /// Route.get('/posts', <dynamic>[AuthMiddleware(optional: true), handler]);
  /// ```
  final bool optional;

  AuthMiddleware({
    this.guard,
    this.guards,
    this.redirectTo,
    this.optional = false,
  }) {
    List<String>? names = guards;
    if (names != null && (names.isEmpty || guard != null)) {
      throw ArgumentError('Set guard or a non-empty guards list, not both.');
    }
  }

  @override
  Future<dynamic> handle(IDoxRequest req) async {
    for (String? name in guards ?? <String?>[guard]) {
      Auth auth = Auth(guard: name);

      // verify token from header and get user data from database
      await auth.verifyToken(req);

      if (auth.isLoggedIn()) {
        req.auth = auth;
        return req;
      }
    }
    if (optional) return req;
    String? page = redirectTo;
    if (page != null && !_wantsJson(req)) return redirect(page);
    throw UnAuthorizedException();
  }

  /// true when `jsonNoRedirect` is on and the client wants JSON.
  static bool _wantsJson(IDoxRequest req) {
    if (!AuthEngine().flags.jsonNoRedirect) return false;
    return req is DoxRequest && req.expectsJson();
  }
}

/// Let only guests through. For
/// login and register pages. A logged-in user goes to [redirectTo]
/// (like `/dashboard`), or gets a 403 when it is null.
/// ```
/// Route.get('/login', <dynamic>[GuestMiddleware(redirectTo: '/dashboard'), handler]);
/// ```
class GuestMiddleware implements IDoxMiddleware {
  /// The guard name from `AuthConfig.guards`.
  /// null uses `AuthConfig.defaultGuard`.
  final String? guard;

  /// Send a logged-in user to this page instead of a 403.
  final String? redirectTo;

  GuestMiddleware({this.guard, this.redirectTo});

  @override
  Future<dynamic> handle(IDoxRequest req) async {
    Auth auth = Auth(guard: guard);
    await auth.verifyToken(req);
    if (auth.guest()) return req;
    String? page = redirectTo;
    if (page != null) return redirect(page);
    throw ForbiddenHttpException(
      message: 'Already logged in',
      errorCode: 'already_logged_in',
    );
  }
}
