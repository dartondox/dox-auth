// ignore_for_file: depend_on_referenced_packages
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart' show sha256;
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart' hide Schema;
import 'package:dox_orm/dox_orm.dart';

/// Opaque access tokens kept in a database table, like AdonisJS access
/// tokens. A token looks like `oat_12.<secret>`.
/// The table keeps only a SHA-256 hash of the secret. You see the plain
/// token once, when you make it. A token works until it expires or you
/// revoke it (the row is deleted).
/// ```
/// AuthGuard(driver: AccessTokenAuthDriver(), provider: AuthProvider(...));
///
/// AccessToken token = await Auth(guard: 'api').createAccessToken(user);
/// return {'token': token.value};
/// ```
/// Make the table with [AccessTokenTables] in a migration.
class AccessTokenAuthDriver extends AuthDriver {
  /// The table name. Use the same name in [AccessTokenTables.up].
  final String table;

  /// The dox_orm connection name. null is the default connection.
  final String? connection;

  /// How long a new token works. null (the default) is no end, like in
  /// AdonisJS. `createAccessToken(expiresIn: ...)` can set it per token.
  final Duration? expiresIn;

  /// The `type` of the tokens of this driver, like `auth_token` in
  /// AdonisJS. null (the default) is the guard name. A token only works
  /// on a guard with the same type, so two access token guards on the
  /// same tables do not take each other's tokens. Set it when you rename
  /// a guard, so its old tokens keep working.
  final String? type;

  /// bcrypt cost of the stored password hashes, for `Auth().attempt`.
  final int hashRounds;

  /// true when the users have text ids. Then `tokenable_id` is a text
  /// column: make the table with `AccessTokenTables.up(schema,
  /// stringIds: true)`. Text ids are compared exactly. false (the
  /// default): the users have int ids, like Sanctum and AdonisJS.
  final bool stringIds;

  /// true when the users have uuid ids. Make the table with
  /// `AccessTokenTables.up(schema, uuidIds: true)`. A uuid is kept and
  /// compared in lower case, like Postgres does.
  final bool uuidIds;

  /// true: an error in a token check is thrown, not turned into "no
  /// user". So the app can answer 503, and a short database problem
  /// does not look like a logout to the client. It is the error as the
  /// database driver or Dart gives it (no wrapper): a database error,
  /// and also a token row that can not be read (eg. a bad date) or a
  /// guard that is not set up. With `AuthMiddleware` it goes to
  /// `AppConfig.exceptionHandler` (a 500 by default).
  /// false (the default): the error is reported and the check gives
  /// null (a 401). A failed `last_used_at` write is never thrown.
  final bool throwOnError;

  bool get _textIds => stringIds || uuidIds;

  AccessTokenAuthDriver({
    this.table = AccessTokenTables.defaultTable,
    this.connection,
    this.expiresIn,
    this.type,
    this.hashRounds = 10,
    this.stringIds = false,
    this.uuidIds = false,
    this.throwOnError = false,
  }) {
    AuthDriver.prepareDummyHash(hashRounds);
  }

  /// The longest token `name` (the column is VARCHAR(255)).
  static const int maxNameLength = 255;

  /// Every token starts with this.
  static const String prefix = 'oat_';

  /// `oat_<row id>.<43 base64url chars>` (32 random bytes)
  static final RegExp _format = RegExp(
    r'^oat_([1-9][0-9]{0,15})\.([A-Za-z0-9_-]{43})$',
  );

  /// `last_used_at` is written at most once in this time per token,
  /// so a busy token does not write on every request.
  static const Duration lastUsedEvery = Duration(minutes: 1);

  static final Random _random = Random.secure();

  QueryBuilder<Map<String, dynamic>> get _query {
    QueryBuilder<Map<String, dynamic>> q = QueryBuilder.table(table);
    String? name = connection;
    return name == null ? q : q.withConnection(name);
  }

  /// the token that [verifyToken] found for a request
  static final Expando<AccessToken> _ofRequest = Expando<AccessToken>();

  /// The token that [verifyToken] found for [req], or null.
  static AccessToken? tokenOf(IDoxRequest req) => _ofRequest[req];

  /// The user of the bearer token of [req], or null. The token is kept
  /// for [tokenOf]. A subclass that overrides this keeps its own checks:
  /// `Auth` always calls it.
  @override
  Future<Model<dynamic>?> verifyToken(IDoxRequest req, String guard) async {
    String? token = JwtAuthDriver.bearerToken(req);
    AccessToken? found = token == null ? null : await check(token, guard);
    _ofRequest[req] = found;
    return found?.user;
  }

  /// Checks [token] without a request (eg. for socket.io).
  /// Gives the token with its `user`, or null when the token has a bad
  /// format, a wrong secret, is expired, revoked, of another type or
  /// user table, or its user is gone. A database error also gives null
  /// (fail closed), and it is reported to `AppConfig.exceptionHandler`.
  /// With [throwOnError], the database error is thrown.
  /// Only a failed `last_used_at` write is reported and then ignored, so
  /// a short write problem does not log users out.
  Future<AccessToken?> check(String token, String guard) async {
    RegExpMatch? match = _format.firstMatch(token);
    if (match == null) return null;
    try {
      Map<String, dynamic>? row = await _query
          .where('id', int.parse(match.group(1)!))
          .getFirst();
      if (row == null) return null;
      AccessToken found = _token(row);
      if (!Hash.equals(found._hash, _hashOf(match.group(2)!))) return null;
      if (found.tokenableType != _tokenableType(guard)) return null;
      if (found.type != _typeOf(guard)) return null;
      DateTime now = DateTime.now().toUtc();
      DateTime? expiresAt = found.expiresAt;
      if (expiresAt != null && !now.isBefore(expiresAt)) return null;

      Model<dynamic> model = AuthEngine().guard(guard).provider.model();
      Model<dynamic>? user = await model.find(found.tokenableId);
      if (user == null) return null;

      /// exact id: MySQL may find 'ABC' for 'abc'
      if (_idOf(user, guard) != found.tokenableId) return null;
      found.user = user;

      DateTime? lastUsed = found.lastUsedAt;
      if (lastUsed == null || now.difference(lastUsed) >= lastUsedEvery) {
        try {
          await _query.where('id', found.id).update(<String, dynamic>{
            'last_used_at': now,
          });
          found.lastUsedAt = now;
        } catch (error, stackTrace) {
          AuthDriver.reportError(error, stackTrace);
        }
      }
      return found;
    } catch (error, stackTrace) {
      if (throwOnError) rethrow;
      AuthDriver.reportError(error, stackTrace);
      return null;
    }
  }

  /// A new token for [user]. Its `value` is the plain token: show it
  /// once, it is not kept. [abilities] default to `['*']` (all).
  Future<AccessToken> create(
    Model<dynamic> user,
    String guard, {
    String? name,
    List<String> abilities = const <String>['*'],
    Duration? expiresIn,
  }) async {
    String secret = _secret();
    _checkName(name);
    DateTime now = DateTime.now().toUtc();
    Duration? ttl = expiresIn ?? this.expiresIn;
    return _insert(
      user,
      guard,
      secret: secret,
      name: name,
      abilities: abilities,
      now: now,
      expiresAt: ttl == null ? null : now.add(ttl),
    );
  }

  Future<AccessToken> _insert(
    Model<dynamic> user,
    String guard, {
    required String secret,
    required String? name,
    required List<String> abilities,
    required DateTime now,
    required DateTime? expiresAt,
  }) async {
    Map<String, dynamic> row = await _query.insert(<String, dynamic>{
      'tokenable_type': _tokenableType(guard),
      'tokenable_id': _idOf(user, guard),
      'type': _typeOf(guard),
      'name': name,
      'hash': _hashOf(secret),
      'abilities': jsonEncode(abilities),
      'last_used_at': null,
      'expires_at': expiresAt,
      'created_at': now,
      'updated_at': now,
    });
    AccessToken token = _token(row);
    token.user = user;
    token.value = '$prefix${token.id}.$secret';
    return token;
  }

  static String _secret() {
    return base64Url
        .encode(List<int>.generate(32, (_) => _random.nextInt(256)))
        .replaceAll('=', '');
  }

  static void _checkName(String? name) {
    if (name != null && name.length > maxNameLength) {
      throw ArgumentError.value(
        name,
        'name',
        'is longer than $maxNameLength characters',
      );
    }
  }

  /// Change the abilities of [token], eg. add `2fa` after the user gave
  /// a two-step code. The plain token stays the same. [guard] must be
  /// the guard of the token (`Auth().setAccessTokenAbilities` passes
  /// it). [token] is changed only after the row was written.
  ///
  /// Throws:
  /// - `ArgumentError` when [token] belongs to another guard (another
  ///   type or user table). Nothing is written.
  /// - [UnAuthorizedException] when the row is gone (revoked).
  Future<void> setAbilities(
    AccessToken token,
    String guard,
    List<String> abilities,
  ) async {
    _checkGuard(token, guard);

    /// a copy, like the lists read from a row
    List<String> list = List<String>.of(abilities);
    int changed = await _own(token).update(<String, dynamic>{
      'abilities': jsonEncode(list),
      'updated_at': DateTime.now().toUtc(),
    });

    /// MySQL counts only changed rows: the same abilities in the same
    /// second (DATETIME has no fraction) give 0. So look again.
    if (changed == 0 && await _own(token).getFirst() == null) {
      throw _revoked();
    }
    token.abilities = list;
  }

  /// A new token in place of [token], for the same user, with the name
  /// and abilities of its row. [token] must have its `user`: use the
  /// token of a checked request, or of `createAccessToken`.
  ///
  /// - [grace]: the old token works this much longer, so calls that are
  ///   on the way do not fail. Default: it ends now. An old token that
  ///   ends sooner keeps its end. In the grace time the old token works
  ///   on every route, also on routes that make tokens. Only a second
  ///   rotate of it is refused (see the next point). So a larger
  ///   [grace] gives a stolen old token more time to be used. Keep it
  ///   short.
  /// - A token can be rotated only once. A second rotate of the same
  ///   old token (in the grace time or after) throws and makes nothing.
  ///   When two rotates run at the same time, one wins.
  /// - [name]: null keeps the name of the old token.
  /// - [expiresIn]: null gives the driver [expiresIn] (no end when that
  ///   is null too). So rotating again and again keeps a login alive
  ///   forever, unless the app sets its own limit.
  ///
  /// It runs in one transaction. The table needs the `rotated_at`
  /// column (see [AccessTokenTables.up]).
  ///
  /// Throws:
  /// - `ArgumentError`: no user on [token], a token or user of another
  ///   guard, a negative [grace], a [grace] or [expiresIn] too large
  ///   for a date, or a [name] that is too long. Nothing is written.
  /// - [UnAuthorizedException] (a 401): the token is revoked, expired,
  ///   or was already rotated. Nothing is written.
  /// - `StateError`: the table has no `rotated_at` column.
  Future<AccessToken> rotate(
    AccessToken token,
    String guard, {
    Duration grace = Duration.zero,
    String? name,
    Duration? expiresIn,
  }) async {
    Model<dynamic>? user = token.user;
    if (user == null) {
      throw ArgumentError('The token has no user. Use a checked token.');
    }
    _checkGuard(token, guard);
    if (_idOf(user, guard) != token.tokenableId) {
      throw ArgumentError('token.user is not the user of the token.');
    }
    if (grace.isNegative) {
      throw ArgumentError.value(grace, 'grace', 'must not be negative');
    }
    _checkName(name);

    /// every value that can throw is made before the first write
    DateTime now = DateTime.now().toUtc();
    DateTime end = _plus(now, grace, 'grace');
    Duration? ttl = expiresIn ?? this.expiresIn;
    DateTime? nextEnd = ttl == null ? null : _plus(now, ttl, 'expiresIn');
    String secret = _secret();

    (AccessToken, DateTime?) result = await QueryBuilder.transaction(
      connection: connection,
      () async {
        Map<String, dynamic>? row = await _own(token).getFirst();
        if (row == null) throw _revoked();
        if (!row.containsKey('rotated_at')) {
          throw StateError(
            "The table '$table' has no rotated_at column. rotate() needs "
            'it. Add it in a new migration: '
            "await schema.table('$table', (Table t) => "
            "t.dateTimeTz('rotated_at').nullable());",
          );
        }

        /// The winner: only one update can set rotated_at from null.
        /// Postgres and MySQL lock the row until the end of this
        /// transaction, so a second update waits, then sees rotated_at
        /// is set and changes 0 rows. SQLite runs one write
        /// transaction at a time.
        int won = await _own(token)
            .whereNull('rotated_at')
            .update(<String, dynamic>{'rotated_at': now, 'updated_at': now});
        if (won == 0) {
          throw UnAuthorizedException(
            message: 'The access token was already rotated.',
          );
        }

        /// read again after the lock, so name and abilities are new
        Map<String, dynamic>? locked = await _own(token).getFirst();
        if (locked == null) throw _revoked();
        AccessToken old = _token(locked);
        if (old.tokenableId != token.tokenableId) throw _revoked();
        DateTime? oldEnd = old.expiresAt;
        if (oldEnd != null && !now.isBefore(oldEnd)) {
          throw UnAuthorizedException(message: 'The access token is expired.');
        }

        AccessToken next = await _insert(
          user,
          guard,
          secret: secret,
          name: name ?? old.name,
          abilities: old.abilities,
          now: now,
          expiresAt: nextEnd,
        );
        if (oldEnd == null || end.isBefore(oldEnd)) {
          await _query.where('id', old.id).update(<String, dynamic>{
            'expires_at': end,
          });
          oldEnd = end;
        }
        return (next, oldEnd);
      },
    );
    token.expiresAt = result.$2;
    return result.$1;
  }

  /// the row of [token], only when it is still of the same type, user
  /// table and user
  QueryBuilder<Map<String, dynamic>> _own(AccessToken token) {
    return _query
        .where('id', token.id)
        .where('type', token.type)
        .where('tokenable_type', token.tokenableType)
        .where('tokenable_id', token.tokenableId);
  }

  /// [token] must be of [guard]: its type and its user table
  void _checkGuard(AccessToken token, String guard) {
    if (token.type != _typeOf(guard) ||
        token.tokenableType != _tokenableType(guard)) {
      throw ArgumentError(
        "The token is not a token of the guard '$guard'. "
        'Use Auth(guard: ...) of its own guard.',
      );
    }
  }

  static UnAuthorizedException _revoked() {
    return UnAuthorizedException(
      message: 'The access token is revoked or does not exist.',
    );
  }

  /// the range of a Dart DateTime, in microseconds from 1970
  static const int _maxMicros = 8640000000000000000;

  /// [now] + [time]. Throws an `ArgumentError` when the date is out of
  /// range: `DateTime.add` does not throw then, it wraps around.
  static DateTime _plus(DateTime now, Duration time, String name) {
    int at = now.microsecondsSinceEpoch;
    int add = time.inMicroseconds;
    if (add > _maxMicros - at || add < -_maxMicros - at) {
      throw ArgumentError.value(time, name, 'is too large');
    }
    return now.add(time);
  }

  /// All tokens of [user] for [guard], newest first. Expired ones too.
  Future<List<AccessToken>> all(Model<dynamic> user, String guard) async {
    Object id = _idOf(user, guard);
    List<Map<String, dynamic>> rows = await _query
        .where('tokenable_type', _tokenableType(guard))
        .where('tokenable_id', id)
        .where('type', _typeOf(guard))
        .orderBy('id', 'desc')
        .get();

    /// exact match: MySQL compares text with no case by default
    return <AccessToken>[
      for (Map<String, dynamic> row in rows)
        if (_token(row) case AccessToken t when t.tokenableId == id) t,
    ];
  }

  /// Delete the token [id] of [user]. false when [user] has no such token.
  Future<bool> revoke(Model<dynamic> user, String guard, int id) async {
    List<AccessToken> own = await all(user, guard);
    if (!own.any((AccessToken t) => t.id == id)) return false;
    return await _query.where('id', id).delete() > 0;
  }

  /// Delete all tokens of [user]. Gives how many were deleted.
  Future<int> revokeAll(Model<dynamic> user, String guard) async {
    Object id = _idOf(user, guard);
    if (!_textIds) {
      /// an int compare in SQL is exact
      return _query
          .where('tokenable_type', _tokenableType(guard))
          .where('tokenable_id', id)
          .where('type', _typeOf(guard))
          .delete();
    }

    /// text: MySQL may match another case, so check the ids in Dart and
    /// delete in chunks (a query has at most 65,535 parameters)
    List<int> ids = <int>[for (AccessToken t in await all(user, guard)) t.id];
    int deleted = 0;
    for (int i = 0; i < ids.length; i += _chunk) {
      List<int> part = ids.sublist(i, min(i + _chunk, ids.length));
      deleted += await _query.whereIn('id', part).delete();
    }
    return deleted;
  }

  static const int _chunk = 1000;

  /// Delete the expired tokens of this table (all types). Gives how many
  /// were deleted. Run it from a scheduled job.
  /// ```
  /// await Auth(guard: 'api').pruneExpiredAccessTokens();
  /// ```
  Future<int> pruneExpired() {
    return _query.where('expires_at', '<=', DateTime.now().toUtc()).delete();
  }

  @override
  Future<Model<dynamic>?> attempt(
    Map<String, dynamic> credentials,
    String guard,
  ) {
    return AuthDriver.checkCredentials(credentials, guard, hashRounds);
  }

  /// Not used: making a token needs the database. `Auth().attempt`
  /// calls [create], and `Auth().login` throws.
  @override
  String? createToken(Map<String, dynamic>? userPayload, String guard) {
    throw StateError(
      'AccessTokenAuthDriver makes tokens with '
      'Auth().createAccessToken(user), not login().',
    );
  }

  /// The table of the users, so a token of one guard does not work for
  /// a guard with another user table.
  String _typeOf(String guard) => type ?? guard;

  static String _tokenableType(String guard) {
    return AuthEngine().guard(guard).provider.model().tableName;
  }

  /// The id of [user]: an int, or a String with [stringIds] or
  /// [uuidIds]. [user] must be a model of the guard, so a token made
  /// for an admin on the users guard can not log in as a user.
  Object _idOf(Model<dynamic> user, String guard) {
    String table = _tokenableType(guard);
    if (user.tableName != table) {
      throw ArgumentError(
        "The user is a '${user.tableName}' model, but the guard '$guard' "
        "uses '$table'. Use Auth(guard: ...) of its own guard.",
      );
    }
    Object? id = user.toMap(original: true)[user.primaryKey];
    if (_textIds ? id is String : id is int && id >= 0) {
      return uuidIds ? (id as String).toLowerCase() : id!;
    }
    throw ArgumentError(
      _textIds
          ? 'The user id must be a String (stringIds or uuidIds is on).'
          : 'The user id must be an int. For text ids, use stringIds: true.',
    );
  }

  AccessToken _token(Map<String, dynamic> row) {
    return AccessToken._fromRow(row, stringIds: _textIds, lowerCase: uuidIds);
  }

  static String _hashOf(String secret) {
    return sha256.convert(utf8.encode(secret)).toString();
  }
}

/// One row of the access token table.
class AccessToken {
  AccessToken._fromRow(
    Map<String, dynamic> row, {
    required bool stringIds,
    required bool lowerCase,
  }) : id = _int(row['id']),
       tokenableType = _text(row['tokenable_type']),
       tokenableId = !stringIds
           ? _int(row['tokenable_id'])
           : lowerCase
           ? _text(row['tokenable_id']).toLowerCase()
           : _text(row['tokenable_id']),
       type = _text(row['type']),
       name = row['name'] == null ? null : _text(row['name']),
       _hash = _text(row['hash']),
       abilities = _abilities(row['abilities']),
       lastUsedAt = _date(row['last_used_at']),
       expiresAt = _date(row['expires_at']),
       createdAt = _date(row['created_at']),
       updatedAt = _date(row['updated_at']);

  final int id;
  final String tokenableType;

  /// The user id: an int, or a String with `stringIds`.
  final Object tokenableId;

  /// The type of the token. See `AccessTokenAuthDriver.type`.
  final String type;
  final String? name;
  final String _hash;
  List<String> abilities;
  DateTime? lastUsedAt;
  DateTime? expiresAt;
  final DateTime? createdAt;
  final DateTime? updatedAt;

  /// The plain token. Only set by `createAccessToken`. It is not kept.
  String? value;

  /// The user of the token. Set by `createAccessToken` and when a
  /// request is checked. null in `accessTokens(user)`.
  Model<dynamic>? user;

  /// true when the token has [ability], or `*` (all).
  bool can(String ability) {
    return abilities.contains('*') || abilities.contains(ability);
  }

  bool cannot(String ability) => !can(ability);

  /// The token without the hash and the plain value.
  Map<String, dynamic> toJson() {
    return <String, dynamic>{
      'id': id,
      'name': name,
      'type': type,
      'abilities': abilities,
      'last_used_at': lastUsedAt?.toIso8601String(),
      'expires_at': expiresAt?.toIso8601String(),
      'created_at': createdAt?.toIso8601String(),
      'updated_at': updatedAt?.toIso8601String(),
    };
  }

  /// drivers give a number as int, or as text (eg. mysql bigint)
  static int _int(Object? value) {
    return value is int ? value : int.parse('$value');
  }

  static String _text(Object? value) {
    if (value is String) return value;
    if (value is Map || value is List) return jsonEncode(value);
    return '$value';
  }

  /// a bad value gives no abilities (fail closed)
  static List<String> _abilities(Object? value) {
    try {
      Object? list = value is List ? value : jsonDecode(_text(value));
      if (list is List) return <String>[for (Object? a in list) '$a'];
    } on FormatException {
      // no abilities
    }
    return const <String>[];
  }

  /// A DateTime, or text from the driver. Times are kept in UTC, so text
  /// with no zone is read as UTC.
  static DateTime? _date(Object? value) {
    if (value == null) return null;
    if (value is DateTime) return value.toUtc();
    String text = '$value'.trim().replaceFirst(' ', 'T');
    bool hasZone = RegExp(r'(Z|[+-]\d\d(:?\d\d)?)$').hasMatch(text);
    return DateTime.parse(hasZone ? text : '${text}Z').toUtc();
  }
}

/// The access token table of [AccessTokenAuthDriver].
/// `dox auth:tokens-table` writes a migration in `db/migration` that calls it:
/// ```
/// class CreateAccessTokensTable extends Migration {
///   @override
///   Future<void> up(Schema schema) async {
///     await AccessTokenTables.up(schema);
///   }
///
///   @override
///   Future<void> down(Schema schema) async {
///     await AccessTokenTables.down(schema);
///   }
/// }
/// ```
/// - `table:`: the driver uses another table name.
/// - `stringIds: true`: the users have text ids. Set it on the driver
///   too. `tokenable_id` is then text, else an unsigned big int.
/// - `uuidIds: true`: the users have uuid ids. `tokenable_id` is then a
///   uuid column (UUID on Postgres), so a foreign key to a uuid id
///   works. Set `uuidIds: true` on the driver too.
/// - `usersTable:`: adds a foreign key from `tokenable_id` to
///   `usersKey` (default `id`) of this table, with cascade delete. So
///   the tokens of a deleted user are deleted too. The id columns must
///   have the same type. Use one token table per user model then.
///
/// It runs on the connection of the migration (the default one).
class AccessTokenTables {
  static const String defaultTable = 'auth_access_tokens';

  static Future<void> up(
    Schema schema, {
    String table = defaultTable,
    bool stringIds = false,
    bool uuidIds = false,
    String? usersTable,
    String usersKey = 'id',
  }) async {
    await schema.create(table, (Table t) {
      t.id();
      t.string('tokenable_type');
      if (uuidIds) {
        t.uuid('tokenable_id');
      } else if (stringIds) {
        t.string('tokenable_id');
      } else {
        t.unsignedBigInteger('tokenable_id');
      }
      t.string('type');
      t.string('name').nullable();
      t.string('hash', 64);
      t.text('abilities');
      // DATETIME on MySQL: TIMESTAMP stops at 2038
      t.dateTimeTz('last_used_at').nullable();
      t.dateTimeTz('expires_at').nullable();
      // set once by rotate(), so a token is rotated only once
      t.dateTimeTz('rotated_at').nullable();
      t.dateTimeTz('created_at').nullable();
      t.dateTimeTz('updated_at').nullable();
      t.index(<String>['tokenable_type', 'tokenable_id']);
      t.index('expires_at');
      if (usersTable != null) {
        t
            .foreign('tokenable_id')
            .references(usersKey)
            .on(usersTable)
            .cascadeOnDelete();
      }
    });
  }

  static Future<void> down(Schema schema, {String table = defaultTable}) async {
    await schema.dropIfExists(table);
  }
}
