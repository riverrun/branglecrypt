## branglecrypt

Erlang bcrypt hashing library.

Branglecrypt uses NIFs (Native Implemented Functions) to call the most expensive
operations. It has recently been updated to stop the NIFs from running too
long, which can cause the Erlang VM scheduler problems, making it more
robust as a result.

So far, `branglecrypt` has only been tested on Linux.

### Usage

There are functions to generate a salt `bcrypt:gen_salt`
and then use that salt to hash a password `bcrypt:hashpw`, but there are
also the following three convenience functions (with examples):

* hashpwsalt -- generate a salt and then use that salt to hash a password

    Hash = bcrypt:hashpwsalt("difficult2guess").

* checkpw -- check the password against the stored hash

    bcrypt:checkpw("difficult2guess", Stored_hash).

* dummy_checkpw -- run a dummy check that always returns false

    bcrypt:dummy_checkpw("difficult2guess").

### License

BSD. For more details, view the `LICENSE` file.
