%%% @doc Adapted base64 implementation for bcrypt.

-module(bbase64).
-export([encode/1, decode/1]).

%% One-based decode map.
-define(DECODE_MAP,
	{bad,bad,bad,bad,bad,bad,bad,bad,ws,ws,bad,bad,ws,bad,bad, %1-15
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad, %16-31
	 ws,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,0,1, %32-47
	 54,55,56,57,58,59,60,61,62,63,bad,bad,bad,eq,bad,bad, %48-63
	 bad,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
	 17,18,19,20,21,22,23,24,25,26,27,bad,bad,bad,bad,bad,
	 bad,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,
	 43,44,45,46,47,48,49,50,51,52,53,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,
	 bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad,bad}).

encode(List) when is_list(List) ->
    encode_l(List).

encode_l([]) ->
    [];
encode_l([A]) ->
    [b64e(A bsr 2),
     b64e((A band 3) bsl 4)];
encode_l([A,B]) ->
    [b64e(A bsr 2),
     b64e(((A band 3) bsl 4) bor (B bsr 4)), 
     b64e((B band 15) bsl 2)];
encode_l([A,B,C|Ls]) ->
    BB = (A bsl 16) bor (B bsl 8) bor C,
    [b64e(BB bsr 18),
     b64e((BB bsr 12) band 63), 
     b64e((BB bsr 6) band 63),
     b64e(BB band 63) | encode_l(Ls)].

decode(List) when is_list(List) ->
    decode_l(List, []).

decode_l([], A) -> A;
decode_l([C1,C2], A) ->
    Bits2x6 = (b64d(C1) bsl 18) bor (b64d(C2) bsl 12),
    Octet1 = Bits2x6 bsr 16,
    lists:append(A, [Octet1]);
decode_l([C1,C2,C3], A) ->
    Bits3x6 = (b64d(C1) bsl 18) bor (b64d(C2) bsl 12)
	bor (b64d(C3) bsl 6),
    Octet1 = Bits3x6 bsr 16,
    Octet2 = (Bits3x6 bsr 8) band 16#ff,
    lists:append(A, [Octet1,Octet2]);
decode_l([C1,C2,C3,C4| Cs], A) ->
    Bits4x6 = (b64d(C1) bsl 18) bor (b64d(C2) bsl 12)
	bor (b64d(C3) bsl 6) bor b64d(C4),
    Octet1 = Bits4x6 bsr 16,
    Octet2 = (Bits4x6 bsr 8) band 16#ff,
    Octet3 = Bits4x6 band 16#ff,
    decode_l(Cs, lists:append(A, [Octet1,Octet2,Octet3])).

%% accessors 
b64e(X) ->
    element(X+1,
	    {$., $/, $A, $B, $C, $D, $E, $F, $G, $H, $I, $J, $K, $L,
             $M, $N, $O, $P, $Q, $R, $S, $T, $U, $V, $W, $X,
             $Y, $Z, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k, $l,
             $m, $n, $o, $p, $q, $r, $s, $t, $u, $v, $w, $x,
             $y, $z, $0, $1, $2, $3, $4, $5, $6, $7, $8, $9}).

b64d(X) ->
    b64d_ok(element(X, ?DECODE_MAP)).

b64d_ok(I) when is_integer(I) -> I;
b64d_ok(_) ->
    erlang:error({badarg}).
