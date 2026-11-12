# Access tokens in detail

A token looks like `oat_12.<secret>`. The table keeps only a SHA-256 hash of the secret.
The plain token is shown once, when you make it. It works until it expires or you revoke it.
The client sends `Authorization: Bearer oat_12.<secret>`.

## Table

`dox auth:tokens-table` writes a migration in `db/migration`. It does not overwrite an existing `create_access_tokens_table`.
Flags: `--uuid`, `--string-ids`, `--users-table=users`, `--users-key=uid`.

The migration by hand:

```dart
// ignore_for_file: file_names
import 'package:dox_auth/dox_auth.dart';
import 'package:dox_migration/dox_migration.dart';

class CreateAccessTokensTable extends Migration {
  @override
  Future<void> up(Schema schema) async {
    await AccessTokenTables.up(schema, usersTable: 'users');
  }

  @override
  Future<void> down(Schema schema) async {
    await AccessTokenTables.down(schema);
  }
}
```

`AccessTokenTables.up` options: `table`, `stringIds`, `uuidIds`, `usersTable`, `usersKey`.
When you set `table`, `stringIds` or `uuidIds`, set the same value on `AccessTokenAuthDriver`.
With more than one user model (users and admins), give each its own token table.

## Manage tokens

```dart
Auth auth = Auth(guard: 'api');
await auth.accessTokens(user);                // list, newest first
await auth.revokeAccessToken(user, id);       // false when not a token of this user
await auth.revokeAllAccessTokens(user);       // after a password change, or when you delete a user
await auth.revokeToken(req);                  // logout: revoke the token of this request
await auth.pruneExpiredAccessTokens();        // delete expired rows, eg. from a scheduled task
```

`Auth(guard: 'api').attempt(credentials)` gives a new token with all abilities (`['*']`), or null.
`createAccessToken` takes `name` (at most 255 characters), `abilities` and `expiresIn`.
`auth.currentAccessToken` is the `AccessToken` of this request. `tokenCan(ability)` is false with no access token.

## Rotate

```dart
AccessToken next = await auth.rotateAccessToken(
  auth.currentAccessToken!,
  grace: const Duration(minutes: 2),
);
```

- The new token keeps the user, name and abilities of the old one.
- A token can be rotated only once. A second rotate throws `UnAuthorizedException` (401).
- `grace` is how long the old token still works. Keep it short.
- A revoked or expired token throws `UnAuthorizedException`. A token of another guard or a negative `grace` throws `ArgumentError`.
- It needs the `rotated_at` column. On an old table, add it: `t.dateTimeTz('rotated_at').nullable();` in a new migration. Without it, rotate throws `StateError`.
- `setAccessTokenAbilities(token, <String>['2fa'])` changes what a token can do.

## Failures

A token gives 401 when its format is bad, the secret is wrong, it is expired or revoked, its user is gone,
it has another type, or it was made for a guard with another user table.
A database error also fails the check. With `AccessTokenAuthDriver(throwOnError: true)` the error is thrown to your `ExceptionHandler` (default answer 500).

- `type` defaults to the guard name. If you rename a guard, set `AccessTokenAuthDriver(type: 'old-name')`.
- `tokenable_type` is the user table name. If you rename the users table, old tokens stop working.
- Pass a user of the guard's model, or `createAccessToken` throws `ArgumentError`.
- `last_used_at` is written at most once a minute per token.
- Expired tokens stay in the table until you prune them.
