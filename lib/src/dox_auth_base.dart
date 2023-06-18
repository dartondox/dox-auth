// ignore_for_file: depend_on_referenced_packages
import 'package:dox_core/dox_core.dart';
import 'package:dox_query_builder/dox_query_builder.dart';

class Auth {
  Guard get guard => Dox().authGuard!;

  Driver get driver => guard.driver;

  Future<void> verifyToken(DoxRequest req) {
    return driver.verifyToken(req);
  }

  bool isLoggedIn() {
    return driver.isLoggedIn();
  }

  T? user<T>() {
    return driver.user<T>();
  }

  Future<String?> attempt(Map<String, dynamic> credentials) {
    return driver.attempt(credentials);
  }

  String login(Model<dynamic> user) {
    return driver.login(user.toJson());
  }

  Map<String, dynamic>? toJson() {
    return driver.toJson();
  }
}
