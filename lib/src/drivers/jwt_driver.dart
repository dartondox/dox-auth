// ignore_for_file: depend_on_referenced_packages
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:dox_core/dox_core.dart';
import 'package:dox_query_builder/dox_query_builder.dart';

class JwtDriver extends Driver {
  /// Jwt secret
  final JWTKey secret;

  /// JWT issuer
  final String? issuer;

  /// JWT algorithm
  final JWTAlgorithm algorithm;

  /// JWT token expire duration
  final Duration? expiresIn;

  /// user data
  Model<dynamic>? _userData;

  /// get auth guard
  Guard get guard => Dox().authGuard!;

  /// get auth provider
  Provider get provider => guard.provider;

  /// constructor
  JwtDriver({
    required this.secret,
    this.algorithm = JWTAlgorithm.HS256,
    this.expiresIn,
    this.issuer,
  });

  /// verify token and get model from provider
  /// and get user data
  @override
  Future<void> verifyToken(DoxRequest req) async {
    try {
      /// get token from header
      String? token = req.header('Authorization')?.replaceFirst('Bearer ', '');

      /// if not token just return
      if (token == null) {
        return;
      }

      /// verify token
      JWT jwt = JWT.verify(token, secret);

      /// get the payload
      Map<String, dynamic> payload = jwt.payload;

      /// get model from provider
      Model<dynamic> model = provider.model();

      /// get id from payload
      dynamic id = payload[model.primaryKey];

      if (id != null) {
        /// by user by id
        _userData = await model.find(id);
      }
    } catch (ex) {
      /// ignore any errors
    }
  }

  /// check user is logged in
  @override
  bool isLoggedIn() {
    return _userData != null;
  }

  /// get user information
  ///```
  /// User user = auth.user<User>();
  ///```
  @override
  T? user<T>() {
    return _userData as T?;
  }

  /// attempt to login
  ///```
  /// String token = await auth.attempt(credentials);
  /// if(token == null) {
  ///   // failed to login
  /// }
  ///```
  @override
  Future<String?> attempt(Map<String, dynamic> credentials) async {
    /// setup new model from auth config
    Model<dynamic> model = provider.model();

    /// setup model query
    Model<dynamic> query = model.debug(model.shouldDebug);

    /// find with credential except password field
    /// since password field is encrypted, we do not need to include
    credentials.forEach((String key, dynamic value) {
      if (key != provider.passwordField &&
          provider.identifierFields.contains(key)) {
        query.where(key, value);
      }
    });

    /// get first record
    _userData = await query.getFirst();

    if (_userData != null) {
      /// convert to json to get password field
      Map<String, dynamic>? jsond = _userData?.toMap(original: true);

      /// verify password
      bool passwordVerified = Hash.verify(
        credentials[provider.passwordField],
        jsond?[provider.passwordField]!,
      );

      if (passwordVerified) {
        /// if password is verify login and get jwt token
        return login(_userData?.toJson());
      }
    }
    return null;
  }

  /// set login and get jwt token
  /// ```
  /// String token = auth.login(user);
  /// ```
  @override
  String login(Map<String, dynamic>? user) {
    JWT jwt = JWT(user, issuer: issuer);
    return jwt.sign(
      secret,
      algorithm: algorithm,
      expiresIn: expiresIn,
    );
  }

  /// support jsonEncode
  @override
  Map<String, dynamic>? toJson() {
    return _userData?.toJson();
  }
}
