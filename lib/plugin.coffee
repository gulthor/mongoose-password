bcrypt = require("bcrypt")

module.exports = (schema, options) ->
  fields =
    password:
      type: String
      required: true

  schema.add(fields)

  schema.pre("save", (next) ->
    # Only hash password if it has been modified (or is new)
    if not @isModified("password")
      return next()

    # Hash password salt
    bcrypt.genSalt(10, (err, salt) =>
      if err
        return next(err)

      bcrypt.hash(@password, salt, (err, hash) =>
        if err
          return next(err)

        @password = hash
        return next()
      )
    )
  )


  schema.method("validatePassword", (candidatePassword, callback) ->
    bcrypt.compare(candidatePassword, @password, (err, isMatch) ->
      if err
        # Passwords do not match
        return callback(err)

      # Passwords match
      return callback(null, isMatch)
    )
  )