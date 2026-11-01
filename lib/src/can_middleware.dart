// ignore_for_file: depend_on_referenced_packages
import 'package:dox_auth/src/auth_exception.dart';
import 'package:dox_auth/src/gate.dart';
import 'package:dox_core/dox_core.dart';

/// Gate checks for the logged-in user of the request (`req.auth`).
/// ```
/// if (await req.can('update', post)) { ... }
/// await req.authorize('update', post); // 401 for a guest, else 403
/// ```
extension GateRequest on IDoxRequest {
  /// the user of `req.auth`, or null for a guest
  Object? get _user => auth?.user<Object>();

  /// true when the user may do [ability] (on [subject]).
  Future<bool> can(String ability, [Object? subject]) {
    return Gate.allows(_user, ability, subject);
  }

  /// true when the user may not do [ability] (on [subject]).
  Future<bool> cannot(String ability, [Object? subject]) {
    return Gate.denies(_user, ability, subject);
  }

  /// Stop the request when the user may not do [ability].
  /// A guest gets 401 (`UnAuthorizedException`), a user gets 403.
  Future<void> authorize(String ability, [Object? subject]) async {
    Object? user = _user;
    GateResponse response = await Gate.inspect(user, ability, subject);
    if (response.allowed) return;
    if (user == null) throw UnAuthorizedException();
    response.authorize();
  }
}

/// Middleware: go on only when the user may do [ability].
/// Put it after `AuthMiddleware`, so `req.auth` is set.
/// A guest gets 401, a user who may not do it gets 403.
/// ```
/// Route.post('posts', <dynamic>[AuthMiddleware(), Can('create', subject: Post), store]);
///
/// Route.bind<Post>('post', (String id) => Post().find(id));
/// Route.put('posts/{post}', <dynamic>[AuthMiddleware(), Can('update', param: 'post'), update]);
/// ```
class Can implements IDoxMiddleware {
  /// the ability name, like `update-post` or a policy method name
  final String ability;

  /// The route param to check, like `post` for `posts/{post}`. The
  /// subject is the value of `Route.bind` for it. No value gives 404.
  final String? param;

  /// A fixed subject, like the type `Post` for a policy `create`.
  final Object? subject;

  const Can(this.ability, {this.param, this.subject});

  @override
  Future<dynamic> handle(IDoxRequest req) async {
    String? name = param;
    Object? target = name == null ? subject : await _bound(req, name);
    await req.authorize(ability, target);
    return req;
  }

  /// the `Route.bind` value of the param [name]. It is kept in
  /// `req.boundValues`.
  static Future<Object> _bound(IDoxRequest req, String name) async {
    if (req is! DoxRequest) {
      throw StateError('Can(param: ...) needs a DoxRequest.');
    }
    Object? found = req.boundValues[name];
    if (found != null) return found;

    Object? raw = req.param[name];
    if (raw == null) throw NotFoundHttpException();
    RouteBinding? binding = Route().bindings[name];
    if (binding == null) {
      throw StateError(
        'Can(param: \'$name\') needs Route.bind for the param "$name".',
      );
    }
    // ponytail: the controller binder runs again later (one more find).
    // dox_core could skip a param that is already in boundValues.
    Object? value = await binding.resolve('$raw');
    if (value == null) throw NotFoundHttpException();
    req.boundValues[name] = value;
    return value;
  }
}
