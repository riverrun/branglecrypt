all: clean compile tests

compile:
	@rebar compile

tests:
	@rebar eunit

clean:
	@rebar clean

