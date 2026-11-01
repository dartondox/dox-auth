import 'dart:async';

import 'package:dox_auth/src/gate.dart';

/// The rules for one model type [M], for users of type [U].
///
/// Write one method per ability. A method gets the user, and the model
/// when the ability needs one. Then list the methods in [abilities].
/// ```
/// class PostPolicy extends Policy<User, Post> {
///   bool create(User user) => user.verified == true;
///   bool update(User user, Post post) => post.userId == user.id;
///
///   @override
///   Map<String, Function> get abilities => <String, Function>{
///     'create': create,
///     'update': update,
///   };
/// }
///
/// Gate.policy<Post>(PostPolicy());
/// await Gate.allows(user, 'update', post);
/// await Gate.allows(user, 'create', Post);
/// ```
/// A method gives a `bool` or a [GateResponse], or a Future of one.
/// A guest is denied, unless [U] is nullable.
abstract class Policy<U, M> {
  /// The ability names and their methods. A method takes `(U user)` or
  /// `(U user, M model)`.
  Map<String, Function> get abilities;

  /// Runs before each method of this policy. A non-null answer decides
  /// at once. Override it, eg. to let admins do anything:
  /// ```
  /// @override
  /// bool? before(User user, String ability) => user.isAdmin ? true : null;
  /// ```
  FutureOr<Object?> before(U user, String ability) => null;

  late final Map<String, Function> _abilities = _checked(abilities);

  /// true when this policy has [ability]
  bool has(String ability) => _abilities.containsKey(ability);

  /// Run [ability] for [user]. [model] is null for an ability with no
  /// model, like `create`.
  Future<GateResponse> check(
    Object? user,
    String ability,
    Object? model,
  ) async {
    Function? method = _abilities[ability];
    if (method == null || user is! U) return const GateResponse.deny();

    Object? early = await before(user, ability);
    if (early != null) return GateResponse.from(early);

    if (model is M && method is FutureOr<Object> Function(U, M)) {
      return GateResponse.from(await method(user, model));
    }
    if (model == null && method is FutureOr<Object> Function(U)) {
      return GateResponse.from(await method(user));
    }
    return const GateResponse.deny();
  }

  /// a method with a wrong signature is a mistake: say it at once
  Map<String, Function> _checked(Map<String, Function> methods) {
    for (MapEntry<String, Function> entry in methods.entries) {
      Function method = entry.value;
      if (method is FutureOr<Object> Function(U) ||
          method is FutureOr<Object> Function(U, M)) {
        continue;
      }
      throw ArgumentError.value(
        entry.key,
        'abilities',
        '$runtimeType: the method must take ($U user) or ($U user, $M model) '
            'and give a bool or a GateResponse',
      );
    }
    return methods;
  }
}
