OSSL	= /usr/lib64/libcrypto.so

test	: test.c test-vectors.c
	${CC} -Wall -Wextra -std=c99 -pedantic -o $@ $^ ${OSSL}

.PHONY	: clean
clean	:
	rm -f test
