-module(bcrypt_tests).
-include_lib("eunit/include/eunit.hrl").
-include("test_vectors.hrl").

openwall_test_() ->
    pairs(?PAIRS_1).

b_prefix_test_() ->
    pairs(?PAIRS_2).

long_pass_test_() ->
    pairs(?PAIRS_3).

pairs(Pairs) ->
    [?_assert(Hash =:= bcrypt:hashpw(Pass, Salt)) ||
     {Pass, Salt, Hash} <- Pairs].

hash_check_test_() ->
    H = bcrypt:hashpwsalt("hardtoguess"),
    [?_assert(bcrypt:checkpw("hardtoguess", H) =:= true),
    ?_assert(bcrypt:checkpw("hatdoguess", H) =:= false),
    ?_assert(bcrypt:checkpw("ohsodifficult", H) =:= false)].

dummy_check_test_() ->
    ?_assert(bcrypt:dummy_checkpw() =:= false).
