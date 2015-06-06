-module(password_tests).
-include_lib("eunit/include/eunit.hrl").

strong_password_test_() ->
    [?_assert(password:strong_password("hfksh6jsdf#") =:= true),
    ?_assert(password:strong_password("8auyk kjkjh") =:= true),
    ?_assert(password:strong_password("ty3uhi@ksd") =:= true)].

weaker_pass_nodigit_test_() ->
    Message = "The password should contain at least one digit and one punctuation character.",
    [?_assert(password:strong_password("hfkshjsdf#") =:= Message),
    ?_assert(password:strong_password("auyk kjkjh") =:= Message),
    ?_assert(password:strong_password("tyuhi@ksd") =:= Message)].

weaker_pass_nopunc_test_() ->
    Message = "The password should contain at least one digit and one punctuation character.",
    [?_assert(password:strong_password("hfksh6jsdf") =:= Message),
    ?_assert(password:strong_password("8auykkjkjh") =:= Message),
    ?_assert(password:strong_password("ty3uhiksd") =:= Message)].

generate_strong_test_() ->
    ?_assert(password:strong_password(password:gen_password()) =:= true).
