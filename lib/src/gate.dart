// ignore_for_file: depend_on_referenced_packages
import 'dart:async';

import 'package:dox_auth/src/policy.dart';
import 'package:dox_core/dox_core.dart';

/// A gate check. It gets the user and the subject (like a post).
/// It gives a `bool` or a [GateResponse], or a Future of one.
typedef GateCheck<U, S> = FutureOr<Object> Function(U user, S subject);

/// A [Gate.before] hook. It gives `true` or `false` (or a
/// [GateResponse]) to decide at once, or `null` to go on.
typedef GateBefore<U> = FutureOr<Object?> Function(U user, String ability);

/// A [Gate.after] hook. It sees the final answer of each check.
typedef GateAfter<U> = FutureOr<void> Function(
  U user,
  String ability,
  GateResponse response,
);

/// The answer of a check: allowed or not, with an optional reason.
/// ```
/// Gate.define('publish', (User user, Post post) {
///   if (post.title == null) return GateResponse.deny('Add a title first');
///   return post.userId == user.id;
/// });
/// ```
class GateResponse {
  /// true when the user may do it
  final bool allowed;

  /// why it was denied. It is the message of the 403 answer.
  final String? message;

  const GateResponse.allow() : allowed = true, message = null;

  const GateResponse.deny([this.message]) : allowed = false;

  bool get denied => !allowed;

  /// Throw a 403 when denied.
  void authorize() {
    if (allowed) return;
    throw ForbiddenHttpException(message: message);
  }

  /// make a [GateResponse] from what a check gave
  static GateResponse from(Object? result) {
    if (result is GateResponse) return result;
    if (result is bool) {
      return result ? const GateResponse.allow() : const GateResponse.deny();
    }
    throw StateError(
      'A gate check must give a bool or a GateResponse, not $result.',
    );
  }
}

/// Gates and policies: who may do what.
///
/// Gates and policies are kept per isolate. Dox runs many isolates, so
/// register them in a `DoxProvider` `setup()`. It runs in every isolate.
/// ```
/// Gate.define('update-post', (User user, Post post) => post.userId == user.id);
/// Gate.policy<Post>(PostPolicy());
///
/// if (await Gate.allows(user, 'update-post', post)) { ... }
/// await Gate.authorize(user, 'update', post); // 403 when denied
/// ```
class Gate {
  static final Map<String, _Rule> _gates = <String, _Rule>{};
  static final Map<Type, Policy<dynamic, dynamic>> _policies =
      <Type, Policy<dynamic, dynamic>>{};
  static final List<_Before<dynamic>> _befores = <_Before<dynamic>>[];
  static final List<_After<dynamic>> _afters = <_After<dynamic>>[];

  /// Add the ability [ability]. [check] gets the user and the subject.
  /// The types come from the function, so a wrong user or subject type
  /// is denied. For no subject, use `_`:
  /// ```
  /// Gate.define('update-post', (User user, Post post) => post.userId == user.id);
  /// Gate.define('create-post', (User user, _) => user.verified == true);
  /// ```
  /// A guest (no user) is denied, unless the user type is nullable:
  /// ```
  /// Gate.define('view-post', (User? user, Post post) => post.published == true);
  /// ```
  static void define<U, S>(String ability, GateCheck<U, S> check) {
    _gates[ability] = _GateRule<U, S>(check);
  }

  /// Add [policy] for the model type [M]. A check with a subject of type
  /// [M] (or the type `M` itself, for abilities with no model) uses it.
  /// ```
  /// Gate.policy<Post>(PostPolicy());
  /// Gate.allows(user, 'update', post);
  /// Gate.allows(user, 'create', Post);
  /// ```
  static void policy<M>(Policy<dynamic, M> policy) {
    policy.has(''); // reads and checks the abilities now, not on a request
    _policies[M] = policy;
  }

  /// Run [hook] before every check. A non-null answer decides at once.
  /// It runs only for users of type [U].
  /// ```
  /// Gate.before((User user, String ability) => user.isAdmin ? true : null);
  /// ```
  static void before<U>(GateBefore<U> hook) {
    _befores.add(_Before<U>(hook));
  }

  /// Run [hook] after every check, eg. to log it.
  /// It runs only for users of type [U]. It can not change the answer.
  static void after<U>(GateAfter<U> hook) {
    _afters.add(_After<U>(hook));
  }

  /// Remove all gates, policies and hooks. For tests.
  static void flush() {
    _gates.clear();
    _policies.clear();
    _befores.clear();
    _afters.clear();
  }

  /// The full answer of a check, with the reason when denied.
  /// [user] is null for a guest. An unknown ability is denied.
  static Future<GateResponse> inspect(
    Object? user,
    String ability, [
    Object? subject,
  ]) async {
    GateResponse response = await _decide(user, ability, subject);
    for (_After<dynamic> hook in _afters) {
      await hook.run(user, ability, response);
    }
    return response;
  }

  /// true when [user] may do [ability] (on [subject]).
  static Future<bool> allows(
    Object? user,
    String ability, [
    Object? subject,
  ]) async {
    return (await inspect(user, ability, subject)).allowed;
  }

  /// true when [user] may not do [ability] (on [subject]).
  static Future<bool> denies(
    Object? user,
    String ability, [
    Object? subject,
  ]) async {
    return (await inspect(user, ability, subject)).denied;
  }

  /// Throw a 403 (`ForbiddenHttpException`) when [user] may not do
  /// [ability]. The message is the reason of `GateResponse.deny`.
  static Future<void> authorize(
    Object? user,
    String ability, [
    Object? subject,
  ]) async {
    (await inspect(user, ability, subject)).authorize();
  }

  /// true when [user] may do at least one of [abilities].
  static Future<bool> any(
    Object? user,
    List<String> abilities, [
    Object? subject,
  ]) async {
    for (String ability in abilities) {
      if (await allows(user, ability, subject)) return true;
    }
    return false;
  }

  /// true when [user] may do all of [abilities].
  static Future<bool> all(
    Object? user,
    List<String> abilities, [
    Object? subject,
  ]) async {
    for (String ability in abilities) {
      if (await denies(user, ability, subject)) return false;
    }
    return true;
  }

  static Future<GateResponse> _decide(
    Object? user,
    String ability,
    Object? subject,
  ) async {
    for (_Before<dynamic> hook in _befores) {
      Object? result = await hook.run(user, ability);
      if (result != null) return GateResponse.from(result);
    }

    // a policy for the subject type first, then the gate
    Policy<dynamic, dynamic>? policy = subject is Type
        ? _policies[subject]
        : _policies[subject?.runtimeType];
    if (policy != null && policy.has(ability)) {
      Object? model = subject is Type ? null : subject;
      return await policy.check(user, ability, model);
    }

    _Rule? gate = _gates[ability];
    if (gate == null) return const GateResponse.deny();
    return await gate.run(user, subject);
  }
}

abstract class _Rule {
  Future<GateResponse> run(Object? user, Object? subject);
}

class _GateRule<U, S> implements _Rule {
  final GateCheck<U, S> check;

  _GateRule(this.check);

  @override
  Future<GateResponse> run(Object? user, Object? subject) async {
    // a guest gets here only when U is nullable
    if (user is! U || subject is! S) return const GateResponse.deny();
    return GateResponse.from(await check(user, subject));
  }
}

class _Before<U> {
  final GateBefore<U> hook;

  _Before(this.hook);

  FutureOr<Object?> run(Object? user, String ability) {
    if (user is! U) return null;
    return hook(user, ability);
  }
}

class _After<U> {
  final GateAfter<U> hook;

  _After(this.hook);

  FutureOr<void> run(Object? user, String ability, GateResponse response) {
    if (user is! U) return null;
    return hook(user, ability, response);
  }
}
