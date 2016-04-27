#include <u.h>
#include <libc.h>
#include <authacl.h>

void
main(int argc, char *argv[])
{
	AuthAcl *acl;
	char *user;
	char *hostname;
	int fd;

	/* get some data and load the acl */
	user = getuser();
	hostname = sysname();
	acl = acl_open("default");
	print("running as %s@%s\n", user, hostname);
	if(acl == nil){
		print("error: could not open acl default!\n");
		exits("fail: open acl acl");
	}

	/* dump the formatted acl */
	print("acl %s {\n", acl->name);
	print("\tglobal status = %d\n", acl->gstatus);
	print("\tstatus = %d\n", acl->status);
	print("\tfilename = %s\n", acl->fname);
	print("\ttotal users = %d\n", acl->tusers);
	print("\tuser list = ");
	for(int i = 0; i < acl->tusers; i++){
		if(i+1 < acl->tusers)
			print("%s, ", acl->unames[i]);
		else
			print("%s", acl->unames[i]);
	}
	print("\n}\n");
	
	/* test current user */
	print("acl_check(%s, %s) = %d\n", acl->name, user,
			acl_check(acl, user));
	print("checkacl(\"%s\", %s) = %d\n", acl->name, user,
			checkacl("default", user));
	print("acl_check(%s, %s) = %d\n", acl->name, "asshole",
			acl_check(acl, "asshole"));
	print("checkacl(\"%s\", %s) = %d\n", acl->name, "asshole",
			checkacl("default", "asshole"));

	/* testing dump of acl */
	free(acl->fname);
	acl->fname = strdup("acldump");
	acl_write(acl);

	/* closes and frees */
	acl_close(acl);
	exits(0);
}
