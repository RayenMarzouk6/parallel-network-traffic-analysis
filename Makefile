CC=gcc
CFLAGS=-O2 -Wall -Wextra -fopenmp -Iinclude
SRC=$(wildcard src/*.c)

network_analyzer: $(SRC) $(wildcard include/*.h)
	$(CC) $(CFLAGS) $(SRC) -o $@

clean:
	rm -f network_analyzer

.PHONY: clean
