-module(password).
-export([gen_password/0, gen_password/1, valid_password/1]).

-define(ALPHA, lists:seq($A, $Z) ++ lists:seq($a, $z)).
-define(DIGITS, "0123456789").
-define(RAND_PUNC, ",./!@#$%^&*();:?<>").
-define(PUNC, " ,./!@#$%^&*();:?<>").
-define(CHAR_MAP, list_to_tuple(?RAND_PUNC ++ ?ALPHA ++ ?DIGITS)).

-define(PASS_LEN, 12).
-define(MIN_PASS_LEN, 8).


%% @doc Function to generate a random password.
gen_password() ->
    rand_password(?PASS_LEN).
gen_password(Len) ->
    rand_password(Len).

rand_password(Len) ->
    case pass_check(rand_numbers(Len)) of
        false -> rand_password(Len);
        Code -> [get_char(X) || X <- Code]
    end.

rand_numbers(Len) ->
    [crypto:rand_uniform(1, 81) || _ <- lists:seq(1, Len)].

pass_check(Code) ->
    lists:any(fun(X) -> X < 19 end, Code) andalso
    lists:any(fun(X) -> X > 70 end, Code) andalso Code.

get_char(Val) ->
    element(Val, ?CHAR_MAP).

%% @doc Function that checks password strength.
valid_password(Password) ->
    case pass_length(length(Password), ?MIN_PASS_LEN) of
        true -> extra_chars(Password);
        Message -> Message
    end.

pass_length(Word_len, Min_len) when Word_len < Min_len ->
    "The password should be at least " ++ integer_to_list(?MIN_PASS_LEN) ++ " characters long.";
pass_length(_, _) ->
    true.

extra_chars(Word) ->
    case has_punc_digit(Word) of
        true -> true;
        _ -> "The password should contain at least one digit and one punctuation character."
    end.

has_punc_digit(Word) ->
    lists:any(fun(X) -> lists:member(X, ?DIGITS) end, Word) andalso
    lists:any(fun(X) -> lists:member(X, ?PUNC) end, Word).
