// ignore_for_file: depend_on_referenced_packages
import 'package:dox_core/dox_core.dart';

/// Too many failed logins for one account from one ip.
/// Dox answers with 429 Too Many Requests.
class LoginThrottledException extends TooManyRequestsException {
  /// How long until the next login try is allowed.
  final Duration retryAfter;

  LoginThrottledException(this.retryAfter)
    : super(
        message:
            'Too many login attempts. Try again in '
            '${(retryAfter.inMilliseconds / 1000).ceil()} seconds.',
      );
}

/// Limits failed logins per account and ip, for `Auth().attempt` and
/// `Auth().attemptSession`. Off by default. Turn it on once at start:
/// ```
/// Auth.throttle = LoginThrottle(maxAttempts: 5, decay: Duration(minutes: 1));
/// ```
/// After [maxAttempts] failed logins for the same login field (eg. the
/// email) and ip, the next try throws [LoginThrottledException] (429)
/// until [decay] has passed since the first failed try. A good login
/// clears the count.
///
/// The counts live in the app cache (`Dox().cache`). Use a shared store
/// like `redis` when you run many isolates or servers.
// ponytail: fixed window from the first failure, like RateLimit of dox_core
class LoginThrottle {
  /// failed logins allowed in one [decay] window
  final int maxAttempts;

  /// how long the count is kept, from the first failed login
  final Duration decay;

  /// the name of the store in `AppConfig.cache`. null is the default store.
  final String? store;

  LoginThrottle({
    this.maxAttempts = 5,
    this.decay = const Duration(minutes: 1),
    this.store,
  }) {
    if (maxAttempts < 1) {
      throw ArgumentError.value(
        maxAttempts,
        'maxAttempts',
        'must be 1 or more',
      );
    }
  }

  CacheStore get _cache => Dox().cache.store(store);

  /// The cache key for a login of [identifiers] from [ip] on [guard].
  /// The login field is trimmed and lower case, so `A@x.com ` and
  /// `a@x.com` share one count.
  static String key(String guard, List<Object?> identifiers, String? ip) {
    List<String> parts = <String>[
      for (Object? value in identifiers) '$value'.trim().toLowerCase(),
    ];
    String who = parts.join('|');
    return 'auth:throttle:$guard:$who|${ip ?? ''}';
  }

  /// Throws [LoginThrottledException] when [key] has too many failures.
  Future<void> check(String key) async {
    Map<String, dynamic> found = await _cache.many(<String>[key, '$key:until']);
    dynamic hits = found[key];
    if (hits is! num || hits < maxAttempts) return;
    dynamic until = found['$key:until'];
    int waitMs = until is num
        ? until.toInt() - DateTime.now().millisecondsSinceEpoch
        : decay.inMilliseconds;
    throw LoginThrottledException(
      Duration(milliseconds: waitMs < 0 ? 0 : waitMs),
    );
  }

  /// Counts one failed login for [key].
  Future<void> hit(String key) async {
    int until = DateTime.now().add(decay).millisecondsSinceEpoch;
    await _cache.add('$key:until', until, decay);
    await _cache.add(key, 0, decay);
    await _cache.increment(key);
  }

  /// Clears the count of [key], after a good login.
  Future<void> clear(String key) async {
    await _cache.forget(key);
    await _cache.forget('$key:until');
  }
}
