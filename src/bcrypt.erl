%%% @doc Erlang NIF implementation of OpenBSD Bcrypt hashing scheme.
%%%      Bcrypt is a key derivation function for passwords designed by Niels Provos
%%%      and David Mazières. Bcrypt is an adaptive hashing function, which means that
%%%      it can be configured to remain slow and resistant to brute-force attacks
%%%      even as computational power increases.
%%%      This bcrypt implementation is based on the latest OpenBSD version, which
%%%      fixed a small issue that affected some passwords longer than 72 characters.

-module(bcrypt).
-export([start/0, stop/0]).
-export([gen_salt/0, gen_salt/1, hashpw/2, checkpw/2, hashpwsalt/1, dummy_checkpw/0]).
-on_load(init/0).

-define(LOGR, 12).

start() ->
    application:start(bcrypt).
stop() ->
    application:stop(bcrypt).

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

%% @doc Initialize the P-box and S-box tables with the digits of Pi,
%%      and then start the key expansion process.
bf_init(_Key, _Key_len, _Salt) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

%% @doc The main key expansion function. This function is called
%%      2^log_rounds times.
bf_expand(_State, _Key, _Key_len, _Salt) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

%% @doc Encrypt and return the hash.
bf_encrypt(_State) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

%% @doc Generate a salt for use with the hashpw function.
%%      The log_rounds parameter determines the computational complexity
%%      of the hashing. Its default is 12, the minimum is 4, and the maximum
%%      is 31.
gen_salt() ->
    gen_salt(?LOGR).

gen_salt(LogRounds) when is_integer(LogRounds), LogRounds > 4, LogRounds < 32 ->
    fmt_salt(binary:bin_to_list(random_bytes(16)), zero_str(LogRounds));
gen_salt(_LogR) ->
    gen_salt(?LOGR).

random_bytes(N) when is_integer(N) ->
    try crypto:strong_rand_bytes(N) of
        RandBytes ->
            RandBytes
    catch
        error:low_entropy ->
            crypto:rand_bytes(N)
    end;
random_bytes(_N) ->
    erlang:error({badarg}).

%% @doc Hash the password using bcrypt.
hashpw(Password, Salt) ->
    {Salt1, _} = lists:split(29, Salt),
    [Prefix, LogRounds, Salt2] = string:tokens(Salt1, "$"),
    Hash = bcrypt(filter_chars(Password, []), Salt2, Prefix, LogRounds),
    fmt_hash(Hash, Salt2, Prefix, LogRounds).

filter_chars([], Acc) -> Acc;
filter_chars([H|T], Acc) when H > 255 ->
    Chars = binary:bin_to_list(unicode:characters_to_binary([H])),
    filter_chars(T, lists:append(Acc, Chars));
filter_chars([H|T], Acc) ->
    filter_chars(T, lists:append(Acc, [H])).

bcrypt(Key, Salt, Prefix, LogRounds) ->
    Key_len = case Prefix of
        "2b" -> min(73, length(Key) + 1);
        _ -> length(Key) + 1
    end,
    {Salt1, Rounds} = prepare_keys(Salt, string:to_integer(LogRounds)),
    State = bf_init(Key, Key_len, Salt1),
    bf_encrypt(expand_keys(State, Key, Key_len, Salt1, Rounds)).

prepare_keys(Salt, {LogRounds, _}) when LogRounds > 4 andalso LogRounds < 32 ->
    {bbase64:decode(Salt), 1 bsl LogRounds};
prepare_keys(_, _) ->
    erlang:error({badarg}).

expand_keys(State, _Key, _Key_len, _Salt, 0) ->
    State;
expand_keys(State, Key, Key_len, Salt, Rounds) ->
    expand_keys(bf_expand(State, Key, Key_len, Salt),
                Key, Key_len, Salt, Rounds - 1).

zero_str(LogRounds) ->
    if LogRounds < 10 -> lists:concat(["0", LogRounds]);
       true -> LogRounds
    end.

fmt_salt(Salt, LogRounds) ->
    lists:concat(["$2b$", LogRounds, "$", bbase64:encode(Salt)]).

fmt_hash(Hash, Salt, Prefix, LogRounds) ->
    lists:concat(["$", Prefix, "$", LogRounds, "$", Salt, bbase64:encode(Hash)]).

%% @doc Convenience function that randomly generates a salt,
%%      and then hashes the password with that salt.
hashpwsalt(Password) ->
    hashpw(Password, gen_salt(?LOGR)).

%% @doc Check the password against the stored hash.
%%      The password and stored hash are compared in constant time
%%      to avoid timing attacks.
checkpw(Plaintext, Stored_hash) ->
    Hash = hashpw(Plaintext, Stored_hash),
    secure_check(Hash, Stored_hash).

%% @doc Perform a dummy check for a user that does not exist.
%%      This always returns false.
%%      The reason for implementing this check is in order to make
%%      user enumeration via timing attacks more difficult.
dummy_checkpw() ->
    hashpwsalt("password"),
    false.

secure_check(Hash, Stored) when is_list(Hash) and is_list(Stored) ->
    case length(Hash) == length(Stored) of
        true -> secure_check(Hash, Stored, 0);
        false -> false
    end;
secure_check(_Hash, _Stored) -> false.

secure_check([H|RestH], [S|RestS], Result) ->
    secure_check(RestH, RestS, (H bxor S) bor Result);
secure_check([], [], Result) ->
    Result == 0.
