compile: ../priv/bcrypt

../priv/bcrypt:
	$(CC) $(CFLAGS) $(ERL_CFLAGS) $(EXE_LDFLAGS) bcrypt.o blowfish.o -shared $(LDFLAGS) $(ERL_LDFLAGS) -lpthread -o ../priv/bcrypt

clean:
	@rm -f ../priv/bcrypt

.PHONY: clean compile
