-module(bcrypt_tests).
-include_lib("eunit/include/eunit.hrl").
-include("test_vectors.hrl").

openwall_test_() ->
    pairs(?PAIRS_1).

b_prefix_test_() ->
    pairs(?PAIRS_2).

long_pass_test_() ->
    pairs(?PAIRS_3).

consistency_test_() ->
    pairs(?PAIRS_4).

pairs(Pairs) ->
    [?_assert(Hash =:= bcrypt:hashpw(Pass, Salt)) ||
     {Pass, Salt, Hash} <- Pairs].

hash_check(Pass, Wrong1, Wrong2, Wrong3) ->
    H = bcrypt:hashpwsalt(Pass),
    [?_assert(bcrypt:checkpw(Pass, H) =:= true),
    ?_assert(bcrypt:checkpw(Wrong1, H) =:= false),
    ?_assert(bcrypt:checkpw(Wrong2, H) =:= false),
    ?_assert(bcrypt:checkpw(Wrong3, H) =:= false)].

hash_check_test_() ->
    hash_check("password", "passwor", "passwords", "pasword"),
    hash_check("hard2guess", "hardguess", "hard 2guess", "had2guess").

hash_check_extended_test_() ->
    hash_check("aáåäeéêëoôö", "aáåäeéêëoö", "aáåeéêëoôö", "aáå äeéêëoôö"),
    hash_check("aáåä eéêëoôö", "aáåä eéê ëoö", "a áåeé êëoôö", "aáå äeéêëoôö").

hash_check_nonascii_test_() ->
    hash_check("Сколько лет, сколько зим", "Сколько лет,сколько зим",
    "Сколько лет сколько зим", "Сколько лет, сколько"),
    hash_check("สวัสดีครับ", "สวัดีครับ", "สวัสสดีครับ", "วัสดีครับ").

hash_check_mixedchars_test_() ->
    hash_check("Я❤três☕ où☔", "Я❤tres☕ où☔", "Я❤três☕où☔", "Я❤três où☔").

dummy_check_test_() ->
    ?_assert(bcrypt:dummy_checkpw() =:= false).

salt_log_num_test_() ->
    [?_assert(lists:prefix("$2b$08$", bcrypt:gen_salt(8)) =:= true),
    ?_assert(lists:prefix("$2b$20$", bcrypt:gen_salt(20)) =:= true)].

salt_length_test_() ->
    [?_assert(length(bcrypt:gen_salt()) == 29),
    ?_assert(length(bcrypt:gen_salt(8)) == 29),
    ?_assert(length(bcrypt:gen_salt(20)) == 29),
    ?_assert(length(bcrypt:gen_salt("wrong input but still works")) == 29)].

salt_wrong_input_test_() ->
    [?_assert(lists:prefix("$2b$12$", bcrypt:gen_salt(3)) =:= true),
    ?_assert(lists:prefix("$2b$12$", bcrypt:gen_salt(32)) =:= true),
    ?_assert(lists:prefix("$2b$12$", bcrypt:gen_salt(["wrong type"])) =:= true)].

hash_wrong_input_test_() ->
    [?_assertError(badarg, bcrypt:hashpw("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCC."))].
