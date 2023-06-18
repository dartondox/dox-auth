// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart';

Future<DoxRequest> doxAuthMiddleware(DoxRequest req) async {
  if (Dox().authGuard == null) {
    return req;
  }

  Auth auth = Auth();

  // verify token from header and get user data from database
  await auth.verifyToken(req);

  if (auth.isLoggedIn()) {
    /// merge into request auth
    req.merge(<String, dynamic>{AUTH_REQUEST_KEY: auth});
    return req;
  }

  throw UnAuthorizedException(message: 'Authentication failed');
}
