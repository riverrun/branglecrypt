-module(password_tests).
-include_lib("eunit/include/eunit.hrl").

valid_password_test_() ->
    [?_assert(password:valid_password("hfksh6jsdf#") =:= true),
    ?_assert(password:valid_password("8auyk kjkjh") =:= true),
    ?_assert(password:valid_password("ty3uhi@ksd") =:= true)].

invalid_pass_nodigit_test_() ->
    Message = "The password should contain at least one digit and one punctuation character.",
    [?_assert(password:valid_password("hfkshjsdf#") =:= Message),
    ?_assert(password:valid_password("auyk kjkjh") =:= Message),
    ?_assert(password:valid_password("tyuhi@ksd") =:= Message)].

invalid_pass_nopunc_test_() ->
    Message = "The password should contain at least one digit and one punctuation character.",
    [?_assert(password:valid_password("hfksh6jsdf") =:= Message),
    ?_assert(password:valid_password("8auykkjkjh") =:= Message),
    ?_assert(password:valid_password("ty3uhiksd") =:= Message)].

generate_valid_test_() ->
    ?_assert(password:valid_password(password:gen_password()) =:= true).
