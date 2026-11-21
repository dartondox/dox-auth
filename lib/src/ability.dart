/// The names of the usual policy abilities, so an editor can suggest them.
/// ```
/// class PostPolicy extends Policy<User, Post> {
///   @override
///   Map<String, Function> get abilities => <String, Function>{
///     Ability.view: view,
///     Ability.update: update,
///   };
/// }
///
/// await Gate.allows(user, Ability.update, post);
/// ```
/// A custom ability is a plain string. Keep it as a constant on the
/// policy, like `static const String publish = 'publish';`.
abstract final class Ability {
  /// list the models
  static const String viewAny = 'viewAny';

  /// read one model
  static const String view = 'view';

  /// make a new model
  static const String create = 'create';

  /// change a model
  static const String update = 'update';

  /// remove a model
  static const String delete = 'delete';
}
