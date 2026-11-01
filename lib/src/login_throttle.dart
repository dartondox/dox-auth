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

  /// The count of [key] and the end of its window (ms since epoch).
  /// Both live in one value, written with a ttl, so a count never lives
  /// without an end. A missing, bad or past value is no count.
  Future<(int, int)?> _read(String key) async {
    List<String> parts = '${await _cache.get(key) ?? ''}'.split('|');
    if (parts.length != 2) return null;
    int? hits = int.tryParse(parts[0]);
    int? until = int.tryParse(parts[1]);
    if (hits == null || until == null) return null;
    if (until <= DateTime.now().millisecondsSinceEpoch) return null;
    return (hits, until);
  }

  /// Throws [LoginThrottledException] when [key] has too many failures.
  Future<void> check(String key) async {
    (int, int)? count = await _read(key);
    if (count == null || count.$1 < maxAttempts) return;
    int waitMs = count.$2 - DateTime.now().millisecondsSinceEpoch;
    throw LoginThrottledException(Duration(milliseconds: waitMs));
  }

  /// Counts one failed login for [key]. The first failure starts the
  /// window of [decay]. Later failures keep the same end.
  // ponytail: read then write, so parallel failures can lose a count.
  // An atomic store op would close it.
  Future<void> hit(String key) async {
    int now = DateTime.now().millisecondsSinceEpoch;
    (int, int)? count = await _read(key);
    int hits = (count?.$1 ?? 0) + 1;
    int until = count?.$2 ?? now + decay.inMilliseconds;
    int ttl = until - now;
    if (ttl < 1) ttl = 1;
    await _cache.put(key, '$hits|$until', Duration(milliseconds: ttl));
  }

  /// Clears the count of [key], after a good login.
  Future<void> clear(String key) => _cache.forget(key);
}
