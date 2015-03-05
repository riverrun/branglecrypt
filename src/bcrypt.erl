%%% @doc Erlang NIF implementation of OpenBSD Bcrypt hashing scheme.
%%%      Bcrypt is a key derivation function for passwords designed by Niels Provos
%%%      and David Mazières. Bcrypt uses a salt to protect against offline attacks.
%%%      It is also an adaptive function, which means that it can be configured
%%%      to remain slow and resistant to brute-force attacks even as computational
%%%      power increases.
%%%      This bcrypt implementation is based on the latest OpenBSD version, which
%%%      fixed a small issue that affected some passwords longer than 72 characters.

-module(bcrypt).
-export([start/0, stop/0]).
-export([gen_salt/0, gen_salt/1, hashpw/2, checkpw/2, hashpwsalt/1, dummy_checkpw/0]).
-on_load(init/0).

-define(LOGR, 12).

start() -> application:start(bcrypt).
stop() -> application:stop(bcrypt).

%% @spec init() -> ok
%% @doc Initialize bcrypt NIF (the functions encode_salt and hashpw).
init() ->
    SoName = filename:join(case code:priv_dir(?MODULE) of
                               {error, bad_name} ->
                                   filename:join(
                                     [filename:dirname(
                                        code:which(?MODULE)),"..","priv"]);
                               Dir ->
                                   Dir
                           end, atom_to_list(?MODULE) ++ "_nif"),
    erlang:load_nif(SoName, 0).

%% @spec gen_salt(integer()) -> string()
%% @doc Generate a salt for use with the hashpw function.
%%      The log_rounds parameter determines the computational complexity
%%      of the hashing. Its default is 12, the minimum is 4, and the maximum
%%      is 31.
%%      The minimum and maximum values are checked by the C code.
gen_salt() ->
    gen_salt(?LOGR).

gen_salt(LogRounds) when is_integer(LogRounds) ->
    R = crypto:rand_bytes(16),
    encode_salt(R, LogRounds);
gen_salt(_LogR) ->
    gen_salt(?LOGR).

encode_salt(_R, _LogRounds) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

%% @spec hashpw(Password::binary(), Salt::binary()) -> string()
%% @doc Hash the password using the OpenBSD Bcrypt scheme.
hashpw(_Password, _Salt) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

%% @spec hashpwsalt(Password::binary()) -> string()
%% @doc Convenience function that randomly generates a salt,
%%      and then hashes the password with that salt.
hashpwsalt(Password) ->
    Salt = gen_salt(?LOGR),
    hashpw(Password, Salt).

%% @spec checkpw(Password::binary(), Hash::binary()) -> boolean()
%% @doc Check the password against the stored hash.
%%      The password and stored hash are compared in constant time
%%      to avoid timing attacks.
checkpw(Plaintext, Stored_hash) ->
    Hash = hashpw(Plaintext, Stored_hash),
    secure_check(Hash, Stored_hash).

%% @spec dummy_checkpw() -> boolean()
%% @doc Perform a dummy check for a user that does not exist.
%%      This always returns false.
%%      The reason for implementing this check is in order to make
%%      user enumeration via timing attacks more difficult.
dummy_checkpw() ->
    checkpw("", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"),
    false.

%% @spec secure_check(Hash::binary() | string(), Stored::binary() | string()) -> boolean()
secure_check(<<Hash/binary>>, <<Stored/binary>>) ->
    secure_check(binary_to_list(Hash), binary_to_list(Stored));
secure_check(Hash, Stored) when is_list(Hash) and is_list(Stored) ->
    case length(Hash) == length(Stored) of
        true -> secure_check(Hash, Stored, 0);
        false -> false
    end;
secure_check(_Hash, _Stored) -> false.

%% @spec secure_check(H::string(), S::string(), Result::integer()) -> boolean()
secure_check([H|RestH], [S|RestS], Result) ->
    secure_check(RestH, RestS, (H bxor S) bor Result);
secure_check([], [], Result) ->
    Result == 0.
