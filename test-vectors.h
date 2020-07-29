#ifndef TEST_VECTORS_H
# define TEST_VECTORS_H

struct test_vector {
	const char *pub;
	const char *sig;
};

extern const char *t_msg;
extern struct test_vector tests[];

#endif
