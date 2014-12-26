%%% @doc Erlang NIF implementation of OpenBSD Bcrypt hashing scheme.

-module(bcrypt).
-export([start/0, stop/0]).
-export([gen_salt/0, gen_salt/1, hashpw/2, checkpw/2]).
-on_load(init/0).

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
    gen_salt(12).

gen_salt(LogRounds) when is_integer(LogRounds) ->
    R = crypto:rand_bytes(16),
    encode_salt(R, LogRounds);
gen_salt(_LogR) ->
    gen_salt(12).

encode_salt(_R, _LogRounds) ->
    nif_stub_error(?LINE).

%% @spec hashpw(Password::binary(), Salt::binary()) -> string()
%% @doc Hash the password using the OpenBSD Bcrypt scheme.
hashpw(_Password, _Salt) ->
    nif_stub_error(?LINE).

nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, Line}).

%% @spec checkpw(Password::binary(), Hash::binary()) -> string()
%% @doc Check the password.
checkpw(Plaintext, Hash) ->
    {ok, Hash} =:= hashpw(Plaintext, Hash).
