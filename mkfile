</$objtype/mkfile

LIB=/$objtype/lib/libauthacl.a
OFILES=\
	acl.$O\
	amount.$O\
	amount_getkey.$O\
	attr.$O\
	auth_attr.$O\
	auth_challenge.$O\
	auth_chuid.$O\
	auth_getkey.$O\
	auth_getuserpasswd.$O\
	auth_proxy.$O\
	auth_respond.$O\
	auth_rpc.$O\
	auth_userpasswd.$O\
	auth_wep.$O\
	login.$O\
	newns.$O\
	noworld.$O\

HFILES=\
	/sys/include/authacl.h\
	authlocal.h\

UPDATE=\
	mkfile\
	$HFILES\
	${OFILES:%.$O=%.c}\
	${LIB:/$objtype/%=/386/%}\

</sys/src/cmd/mksyslib
