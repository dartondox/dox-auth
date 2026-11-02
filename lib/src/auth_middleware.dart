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

  /// Send a guest to this page (like `/login`) instead of a 401.
  /// For web pages. null gives the 401.
  final String? redirectTo;

  /// Let guests through too. A good login still sets `req.auth`, so
  /// `req.can()` and `req.auth?.user()` work on a public page. A guest,
  /// or a bad or expired token, goes on with `req.auth` null. A database
  /// error also goes on as a guest, but it is reported (see
  /// `AuthDriver.reportError`).
  /// ```
  /// Route.get('/posts', <dynamic>[AuthMiddleware(optional: true), handler]);
  /// ```
  final bool optional;

  AuthMiddleware({this.guard, this.redirectTo, this.optional = false});

  @override
  Future<dynamic> handle(IDoxRequest req) async {
    Auth auth = Auth(guard: guard);

    // verify token from header and get user data from database
    await auth.verifyToken(req);

    if (auth.isLoggedIn()) {
      req.auth = auth;
      return req;
    }
    if (optional) return req;
    String? page = redirectTo;
    if (page != null) return redirect(page);
    throw UnAuthorizedException();
  }
}

/// Let only guests through, like the Laravel `guest` middleware. For
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
