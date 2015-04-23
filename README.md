## branglecrypt

Erlang / C bcrypt hashing library.

### Usage

There are functions to generate a salt `bcrypt:gen_salt`
and then use that salt to hash a password `bcrypt:hashpw`, but there are
also the following three convenience functions (with examples):

* hashpwsalt -- generate a salt and then use that salt to hash a password

    Hash = bcrypt:hashpwsalt("difficult2guess").

* checkpw -- check the password against the stored hash

    bcrypt:checkpw("difficult2guess", Stored_hash).

* dummy_checkpw -- run a dummy check that always returns false

    bcrypt:dummy_checkpw().

### License

BSD. For more details, view the `LICENSE` file.
