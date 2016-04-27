#include <u.h>
#include <libc.h>
#include <bio.h>
#include <authacl.h>

AuthAcl*
acl_open(char *name)
{
	Biobuf *b, *ba;
	char *s;
	char *toks[3];
	AuthAcl *buf;
	int top = 1;
	int i = 0;

	buf = malloc(sizeof(AuthAcl));
	if(buf == nil)
		return nil;
	b = Bopen("/adm/acls", OREAD);
	if(b == nil){
		free(buf);
		return nil;
	}
	while((s = Brdline(b, '\n')) != nil){
		s[Blinelen(b)-1] = 0;
		if(top){
			if(strncmp(s, "check", strlen(s)) == 0)
				buf->gstatus = AclCheck;
			else if(strncmp(s, "pass", strlen(s)) == 0)
				buf->gstatus = AclPass;
			else
				buf->gstatus = AclFail;
			top = 0;
			continue;
		}
		if(tokenize(s, toks, 3) == 3){
			if(strncmp(toks[0], "acl", strlen(toks[0])))
				continue;
			if(strcmp(toks[1], name) == 0){
				buf->name = strdup(name);
				buf->fname = strdup(toks[2]);
				Bterm(b);
				break;
			}
		}
	}
	if(buf->fname == nil){
		free(buf);
		return nil;
	}

	ba = Bopen(buf->fname, OREAD);
	if(ba == nil){
		free(buf->name);
		free(buf->fname);
		free(buf);
		return nil;
	}
	top = 0;
	while((s = Brdline(ba, '\n')) != nil){
		s[Blinelen(b)-1] = 0;
		if(top == 0){
			if(tokenize(s, toks, 2) != 2){
				Bterm(ba);
				free(buf->name);
				free(buf->fname);
				free(buf);
				return nil;
			}
			buf->tusers = atoi(toks[1]);
			buf->unames = malloc(sizeof(char*)*buf->tusers);
			top++;
			continue;
		} else if(top == 1) {
			if(strncmp(s, "check", strlen(s)) == 0)
				buf->status = AclCheck;
			else if(strncmp(s, "pass", strlen(s)) == 0)
				buf->status = AclPass;
			else
				buf->status = AclFail;
			top++;
			continue;
		} else {
			if(tokenize(s, toks, 2) != 2)
				continue;
			if(strcmp(toks[0], "user") == 0){
				if(i >= buf->tusers)
					break;
				buf->unames[i] = strdup(toks[1]);
				i++;
			}
		}
	}
	Bterm(ba);
	return buf;
}

int
acl_write(AuthAcl *acl)
{
	Biobuf *b;

	b = Bopen(acl->fname, OTRUNC|OWRITE);
	if(b == nil)
		return -1;
	Bprint(b, "len %d\n", acl->tusers);
	switch(acl->status){
	case AclCheck:
		Bprint(b, "check\n");
		break;
	case AclPass:
		Bprint(b, "pass\n");
		break;
	case AclFail:
	default:
		Bprint(b, "fail\n");
		break;
	}
	for(int i = 0; i < acl->tusers; i++)
		Bprint(b, "user %s\n", acl->unames[i]);
	Bterm(b);
	return 0;
}

int
acl_close(AuthAcl *acl)
{
	free(acl->fname);
	free(acl->name);
	for(int i = 0; i < acl->tusers; i++)
		free(acl->unames[i]);
	free(acl->unames);
	free(acl);
	return 0;
}

int
acl_check(AuthAcl *acl, char *user)
{
	if(acl->gstatus == AclPass || acl->status == AclPass)
		return 1;
	else if(acl->gstatus == AclFail || acl->status == AclFail)
		return 0;
	else {
		for(int i = 0; i < acl->tusers; i++){
			if(strcmp(user, acl->unames[i]) == 0)
				return 1;
		}
	}
	return 0;
}

int
checkacl(char *name, char *user)
{
	AuthAcl *a;
	int st;

	a = acl_open(name);
	if(a == nil)
		return 0;
	st = acl_check(a, user);
	acl_close(a);
	return st;
}
