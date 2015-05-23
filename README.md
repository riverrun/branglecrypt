# branglecrypt

Erlang / C bcrypt hashing library.

## Features

* Branglecrypt is secure and easy to use.
* None of the NIFs run for a long time.
* There are also functions for generating random passwords and validating
passwords for password strength.

## Usage

There are functions to generate a salt `bcrypt:gen_salt`
and then use that salt to hash a password `bcrypt:hashpw`, but there are
also the following three convenience functions (with examples):

* hashpwsalt -- generate a salt and then use that salt to hash a password

    Hash = bcrypt:hashpwsalt("difficult2guess").

* checkpw -- check the password against the stored hash

    bcrypt:checkpw("difficult2guess", Stored_hash).

* dummy_checkpw -- run a dummy check that always returns false

    bcrypt:dummy_checkpw().

### Generating and validating passwords

* gen_password -- generate a random password (the default length is 12 characters)

    Password = password:gen_password().
    Password = password:gen_password(16).

* valid_password -- checks that a password is long enough and contains at least
one digit and one punctuation character.

    password:valid_password(Password).

## License

BSD. For more details, view the `LICENSE` file.
