// ignore_for_file: depend_on_referenced_packages
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart' show sha256;
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_core/dox_core.dart' hide Schema;
import 'package:dox_orm/dox_orm.dart';

/// Opaque access tokens kept in a database table, like AdonisJS access
/// tokens or Laravel Sanctum. A token looks like `oat_12.<secret>`.
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

  /// true when the users have text ids (like a uuid). Then
  /// `tokenable_id` is a text column: make the table with
  /// `AccessTokenTables.up(schema, stringIds: true)`. false (the
  /// default): the users have int ids, like Sanctum and AdonisJS.
  final bool stringIds;

  AccessTokenAuthDriver({
    this.table = AccessTokenTables.defaultTable,
    this.connection,
    this.expiresIn,
    this.type,
    this.hashRounds = 10,
    this.stringIds = false,
  }) {
    AuthDriver.prepareDummyHash(hashRounds);
  }

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
    String secret = base64Url
        .encode(List<int>.generate(32, (_) => _random.nextInt(256)))
        .replaceAll('=', '');
    DateTime now = DateTime.now().toUtc();
    Duration? ttl = expiresIn ?? this.expiresIn;
    Map<String, dynamic> row = await _query.insert(<String, dynamic>{
      'tokenable_type': _tokenableType(guard),
      'tokenable_id': _idOf(user),
      'type': _typeOf(guard),
      'name': name,
      'hash': _hashOf(secret),
      'abilities': jsonEncode(abilities),
      'last_used_at': null,
      'expires_at': ttl == null ? null : now.add(ttl),
      'created_at': now,
      'updated_at': now,
    });
    AccessToken token = _token(row);
    token.user = user;
    token.value = '$prefix${token.id}.$secret';
    return token;
  }

  /// All tokens of [user] for [guard], newest first. Expired ones too.
  Future<List<AccessToken>> all(Model<dynamic> user, String guard) async {
    Object id = _idOf(user);
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
    List<AccessToken> own = await all(user, guard);
    if (own.isEmpty) return 0;
    return _query.whereIn('id', <int>[
      for (AccessToken t in own) t.id,
    ]).delete();
  }

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

  /// The id of [user]: an int, or a String with [stringIds].
  Object _idOf(Model<dynamic> user) {
    Object? id = user.toMap(original: true)[user.primaryKey];
    if (stringIds ? id is String : id is int && id >= 0) return id!;
    throw ArgumentError(
      stringIds
          ? 'The user id must be a String (stringIds is on).'
          : 'The user id must be an int. For text ids, use stringIds: true.',
    );
  }

  AccessToken _token(Map<String, dynamic> row) {
    return AccessToken._fromRow(row, stringIds: stringIds);
  }

  static String _hashOf(String secret) {
    return sha256.convert(utf8.encode(secret)).toString();
  }
}

/// One row of the access token table.
class AccessToken {
  AccessToken._fromRow(Map<String, dynamic> row, {required bool stringIds})
    : id = _int(row['id']),
      tokenableType = _text(row['tokenable_type']),
      tokenableId = stringIds
          ? _text(row['tokenable_id'])
          : _int(row['tokenable_id']),
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
  final List<String> abilities;
  DateTime? lastUsedAt;
  final DateTime? expiresAt;
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
/// Add a migration in `db/migration` that calls it:
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
/// - `usersTable:`: adds a foreign key from `tokenable_id` to `id` of
///   this table, with cascade delete. So the tokens of a deleted user
///   are deleted too. The id columns must have the same type.
///
/// It runs on the connection of the migration (the default one).
class AccessTokenTables {
  static const String defaultTable = 'auth_access_tokens';

  static Future<void> up(
    Schema schema, {
    String table = defaultTable,
    bool stringIds = false,
    String? usersTable,
  }) async {
    await schema.create(table, (Table t) {
      t.id();
      t.string('tokenable_type');
      if (stringIds) {
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
      t.dateTimeTz('created_at').nullable();
      t.dateTimeTz('updated_at').nullable();
      t.index(<String>['tokenable_type', 'tokenable_id']);
      if (usersTable != null) {
        t
            .foreign('tokenable_id')
            .references('id')
            .on(usersTable)
            .cascadeOnDelete();
      }
    });
  }

  static Future<void> down(Schema schema, {String table = defaultTable}) async {
    await schema.dropIfExists(table);
  }
}
