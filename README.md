##branglecrypt

Erlang wrapper for OpenBSD bcrypt.

This application is based on [erlang-bcrypt](https://github.com/opscode/erlang-bcrypt),
but it is a lot more lightweight, and it uses an updated version of the
OpenBSD Bcrypt hashing scheme.

So far, `branglecrypt` has only been tested on Linux.

###Usage

There are functions to generate a salt `bcrypt:gen_salt`
and then use that salt to hash a password `bcrypt:hashpw`, but there are
also the following three convenience functions (with examples):

hashpwsalt -- generate a salt and then use that salt to hash a password

    Hash = bcrypt:hashpwsalt("difficult2guess").

checkpw -- check the password against the stored hash

    bcrypt:checkpw("difficult2guess", Stored_hash).

dummy_checkpw -- run a dummy check that always returns false

    bcrypt:dummy_checkpw("difficult2guess").

