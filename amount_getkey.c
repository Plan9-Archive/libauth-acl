#include <u.h>
#include <libc.h>
#include <authacl.h>

int (*amount_getkey)(char*) = auth_getkey;
