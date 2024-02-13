/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h" 
#include <signal.h>
#include<time.h>

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define MAX_FAILED_ATTEMPTS 3

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	signal (SIGINT, SIG_IGN);

	//printf ("ignoring ctrl-c \n");

	signal (SIGTSTP,SIG_IGN);

	//printf("ignoring ctrl-z \n");

}

char* generate_salt() {
    static char salts[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    static char generated_salt[3]; // 2 characters + null terminator

    // Omitting dynamic seeding of srand() for demonstration
	srand((unsigned int)time(NULL));
    
    // Randomly select two characters from the salts array
    for (int i = 0; i < 2; i++) {
        int rand_index = rand() % strlen(salts); // Generate a random index
        generated_salt[i] = salts[rand_index]; // Assign the character at the random index to the salt
    }

    generated_salt[2] = '\0'; // Null-terminate the string

    return generated_salt;
}



int main(int argc, char *argv[1]) {

	//struct passwd *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */
	mypwent *passwddata;

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
	char *encrypt_pass;
	char *repass;
	int update;

	char *newsalt;
	char *new_pass;
	char temp;
	char *shell = "/bin/sh"; // Path to the shell

	sighandler();


	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		/*if (gets(user) == NULL)  gets() is vulnerable to buffer */
			/*exit(0);   overflow attacks.  */
        
        if (fgets(user, sizeof(user), stdin) == NULL) {
              // Handle EOF or error
			  exit(0);
        } else {
            // Remove the newline character fgets() reads and stores
            size_t len = strlen(user);
                   if (len > 0 && user[len - 1] == '\n') {
             user[len - 1] = '\0';
    }
}


		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {

		     encrypt_pass= crypt(user_pass, passwddata->passwd_salt);

			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			if (!strcmp(encrypt_pass, passwddata->passwd)) {

				printf(" You're in !\n");
				passwddata->pwage +=1;
				passwddata->pwfailed=0;
				mysetpwent(user,passwddata);

				if (passwddata->pwage >2)
				{
					printf ("Limit Exceeded, You should change your password.\n");
                    printf("Want to change the password? Type: y/n \n");
			
					scanf("%c", &temp);
					if (temp =='y')
					{

						printf("Enter new password:\n");

						new_pass=getpass(prompt);

						newsalt=generate_salt();
						passwddata->passwd_salt= newsalt;
                        repass = crypt(new_pass, passwddata->passwd_salt);
						passwddata->passwd =repass;

						passwddata->pwage=0;
						passwddata->pwfailed=0;
						update =mysetpwent(user, passwddata);

						if (update==0)
						{
							printf("Password changed successfully\n");
						}
						else
						{
                           printf ("Failed to change the password\n");
					    }
					}

					else
					{
                      printf("Password change is Required!!\n");
					}
				}	

				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

				// Set the user ID to the logged in user
                 if (setuid(passwddata->uid) != 0) {
                  perror("setuid failed");
                 exit(EXIT_FAILURE);
                }

                // Replace the current process with a new shell
    
                char *args[] = {shell, NULL}; //argument list for the shell
                execve(shell, args, NULL); // Environment passed as NULL for simplicity

                // If execve returns, it must have failed
                perror("execve failed");
                exit(EXIT_FAILURE);
			
			}

            else
			{  
                //printf("Login failed!s \n");
				passwddata->pwfailed += 1;
				update= mysetpwent(user,passwddata);
				if (passwddata->pwfailed >= MAX_FAILED_ATTEMPTS)
				{
					printf("Maximum login attempt reached! Try again after 10 seconds\n");
					passwddata->pwfailed =0;
				    sleep(10);			
				}
                else
				{

					printf("You have %d attempts left \n", MAX_FAILED_ATTEMPTS - passwddata->pwfailed );
				}


			    update= mysetpwent(user, passwddata);

			    if (update !=0) 
			    {
				printf("Update status of login attempts unsuccessful \n");
			    }
			}


		}

		else 
		{
			printf("No Data\n");
			return 0;
		}
	}
	return 0;
}
