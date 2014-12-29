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

salt_log_num_test_() ->
    [?_assert(lists:prefix("$2b$08$", bcrypt:gen_salt(8)) =:= true),
    ?_assert(lists:prefix("$2b$20$", bcrypt:gen_salt(20)) =:= true)].

salt_wrong_input_test_() ->
    [?_assert(lists:prefix("$2b$04$", bcrypt:gen_salt(3)) =:= true),
    ?_assert(lists:prefix("$2b$31$", bcrypt:gen_salt(32)) =:= true),
    ?_assert(lists:prefix("$2b$12$", bcrypt:gen_salt(["wrong type"])) =:= true)].

hash_wrong_input_test_() ->
    [?_assertError(badarg, bcrypt:hashpw("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCC.")),
    ?_assertError(badarg, bcrypt:hashpw(["U*U"], "$2a$05$CCCCCCCCCCCCCCCCCCCCC."))].
