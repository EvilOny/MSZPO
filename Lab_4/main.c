#include <stdio.h>
#include <string.h>
#include <stdlib.h>
struct data
{
char pass[8];
int user_id;
int (*get_shell) (unsigned short int, char *);
};

void user_priv (void);
void admin_priv (void);
void system_priv (void);
void get_shell (unsigned short int, char *);

void
get_shell (unsigned short int user_id, char *pass)
{

if (user_id == 128)
	{

system_priv ();

}

if (user_id == 256 && !strcmp ("qwerty", pass))
	{

user_priv ();

}

if (user_id == 512 && !strcmp ("asdfgh", pass))
	{

admin_priv ();

}

}


void
user_priv (void)
{

printf ("ACCESS GRANTED. You have shell with USER privileges.\n");

}
void

admin_priv (void)
{

printf ("ACCESS GRANTED. You have shell with ADMIN privileges.\n");

}
void

system_priv (void)
{

printf ("ACCESS GRANTED. You have shell with SYSTEM privileges.\n");

}

void

main (int argc, char *argv[])
{

if (argc != 3)
	{

printf ("USAGE: ./prog12 <user_id> <password>\n");

return;

}

if (atoi (argv[1]) < 256)
	{

printf ("ERROR: user id must be more than 256.\n");

return;

}

struct data *auth;

auth = malloc (sizeof (struct data));

auth->user_id = atoi (argv[1]);

auth->get_shell = get_shell;

strcpy (auth->pass, argv[2]);

printf("user_id %llx pass %llx \n",auth->user_id, auth->pass);

auth->get_shell (auth->user_id, auth->pass);

free (auth);

}
