import 'package:dox_auth/dox_auth.dart';
import 'package:dox_auth/src/hash.dart';
import 'package:test/test.dart';

void main() {
  group('Hash |', () {
    test('make/verify', () {
      String secret = '4HyiSrq4N5Nfg6bOadIhbFEI8zbUkpxt';
      String hashedPassword = Hash.make(secret);
      bool result = Hash.verify(secret, hashedPassword);
      expect(result, true);
    });

    test('invalid should return false', () {
      String secret = '4HyiSrq4N5Nfg6bOadIhbFEI8zbUkpxt';
      String hashedPassword = Hash.make(secret);
      bool result = Hash.verify('password', hashedPassword);
      expect(result, false);
    });
    test('makeAsync/verifyAsync run bcrypt in another isolate', () async {
      String hashed = await Hash.makeAsync('secret');
      expect(await Hash.verifyAsync('secret', hashed), true);
      expect(await Hash.verifyAsync('wrong', hashed), false);
      expect(await Hash.verifyAsync('secret', 'not-a-hash'), false);
      expect(Hash.verify('secret', hashed), true);
    });

    test('Auth.hashCost reads the cost from a hash', () {
      expect(Auth.hashCost(Hash.make('secret', rounds: 4)), 4);
      expect(Auth.hashCost(r'$2b$12$abc'), 12);
      expect(Auth.hashCost(r'$2y$11$abc'), 11);
      expect(Auth.hashCost('not-a-hash'), isNull);
    });

    test('Auth.needsRehash is true when the cost is not Hash.rounds', () {
      String low = Hash.make('secret', rounds: 4);
      expect(Auth.needsRehash(low), isTrue);
      expect(Auth.needsRehash(low, rounds: 4), isFalse);
      expect(Auth.needsRehash(Hash.make('secret')), isFalse);
      expect(Auth.needsRehash('not-a-hash'), isTrue);
      Hash.rounds = 4;
      addTearDown(() => Hash.rounds = 10);
      expect(Auth.needsRehash(low), isFalse);
    });

    test('rounds sets the bcrypt cost', () async {
      expect(Hash.make('secret', rounds: 4), startsWith(r'$2a$04$'));
      expect(await Hash.makeAsync('secret', rounds: 5), startsWith(r'$2a$05$'));
      expect(Hash.make('secret'), startsWith(r'$2a$10$'));
      Hash.rounds = 4;
      addTearDown(() => Hash.rounds = 10);
      String hashed = Hash.make('secret');
      expect(hashed, startsWith(r'$2a$04$'));
      expect(Hash.verify('secret', hashed), true);
    });
  });
}
