-module(bcrypt_tests).
-include_lib("eunit/include/eunit.hrl").

-define(
   PAIRS_1,
   % From the Openwall implementation: http://www.openwall.com/crypt/
   [{"U*U",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
    {"U*U*",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"},
    {"U*U*U",
     "$2a$05$XXXXXXXXXXXXXXXXXXXXXO",
     "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"},
    {"",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
    {"0123456789abcdefghijklmnopqrstuvwxyz"
     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
     "$2a$05$abcdefghijklmnopqrstuu",
     "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"}]).

-define(
   PAIRS_2,
   % OpenBSD test vectors (including hashes with the 2b prefix)
   [{"\xa3",
     "$2b$05$/OK.fbVrR/bpIqNJ5ianF.",
     "$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
    {"\xa3",
     "$2a$05$/OK.fbVrR/bpIqNJ5ianF.",
     "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
    {"\xff\xff\xa3",
     "$2b$05$/OK.fbVrR/bpIqNJ5ianF.",
     "$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"},
    {"000000000000000000000000000000000000000000000000000000000000000000000000",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.6.O1dLNbjod2uo0DVcW.jHucKbPDdHS"},
    {"000000000000000000000000000000000000000000000000000000000000000000000000",
     "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2b$05$CCCCCCCCCCCCCCCCCCCCC.6.O1dLNbjod2uo0DVcW.jHucKbPDdHS"}]).

-define(
   PAIRS_3,
   % Passwords longer than 72 chars (from OpenBSD test vectors)
   [{"012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234",
     "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2b$05$CCCCCCCCCCCCCCCCCCCCC.XxrQqgBi/5Sxuq9soXzDtjIZ7w5pMfK"},
   {"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345",
     "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2b$05$CCCCCCCCCCCCCCCCCCCCC.XxrQqgBi/5Sxuq9soXzDtjIZ7w5pMfK"}]).

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
