#include <time.h>
#include "helper.h"

int main(int argc, char *argv[])
{
    if (argc == 3)
    {
        int bufferlen = strlen(argv[1]);
        char subbuff[5];
        memcpy(subbuff, &argv[1][bufferlen - 4], 4);
        subbuff[4] = '\0';
        if (strcasecmp(subbuff, ".txt") != 0)
        {
            printf("[%s] must be a .txt file\n", argv[1]);
            return 1;
        }
        bufferlen = strlen(argv[2]);
        memcpy(subbuff, &argv[2][bufferlen - 4], 4);
        subbuff[4] = '\0';
        if (strcasecmp(subbuff, ".txt") != 0)
        {
            printf("[%s] must be a .txt file\n", argv[2]);
            return 1;
        }
    }
    else
    {
        puts("Provide exactly two command line arguments in the following format: [data].txt [datakeys].txt");
        return 2;
    }
    srand(time(0));
    gen_key_candidates();
    if (!load_accounts(argv[1], argv[2]))
    {
        puts("Failed to load accounts successfully.");
        return 3;
    }
    puts("Welcome! Type a number associated with the following options to get started.");
    char masterusername[MUSERNAMESIZE + 1] = {0};
    char masterpassword[MPASSWORDSIZE + 1] = {0};
    char userfile[MUSERNAMESIZE + 5] = {0};
    int option = 0;
    for (;;)
    {
        memset(masterusername, '\0', MUSERNAMESIZE + 1);
        memset(masterpassword, '\0', MPASSWORDSIZE + 1);
        memset(userfile, '\0', MUSERNAMESIZE + 5);
        option = 0;
        puts("1. Sign into account\n2. Create an account\n3. Modify an account's login credentials\n4. Delete an account\n5. Exit Program\n");
        scanf("%d", &option);
        if (option == 1)
        {
            puts("Enter your username: ");
            scanf("%s", masterusername);
            puts("Enter your password: ");
            scanf("%s", masterpassword);
            if (account_exists(masterusername, masterpassword, argv[2]))
            {
                puts("Login was successful");
            }
            else
            {
                puts("Account doesn't exist. Login was unsuccessful");
                continue;
            }
            if (!open_userfile(userfile, masterusername))
            {
                puts("Failed to load user file successfully.");
                continue;
            }
            puts("User file loaded successfully.");
            int vaultlen = 0;
            record *vault;
            if (!load_vault(userfile, &vault, &vaultlen))
            {
                puts("Unable to successfully load in vault");
                continue;
            }
            int vaultoption = 0;
            char username[MUSERNAMESIZE + 1] = {0};
            char password[MPASSWORDSIZE + 1] = {0};
            char newusername[MUSERNAMESIZE + 1] = {0};
            char newpassword[MPASSWORDSIZE + 1] = {0};
            char website[URLSIZE + 1] = {0};
            int rank = 0;
            for (;;)
            {
                rank = 0;
                vaultoption = 0;
                memset(username, '\0', MUSERNAMESIZE + 1);
                memset(password, '\0', MPASSWORDSIZE + 1);
                memset(newusername, '\0', MUSERNAMESIZE + 1);
                memset(newpassword, '\0', MPASSWORDSIZE + 1);
                memset(website, '\0', URLSIZE + 1);
                puts("1. View vault's records\n2. Add a record\n3. Modify a record\n4. Delete a record\n5. Delete vault\n6. Exit to main screen\n7. Exit Program\n");
                scanf("%d", &vaultoption);
                if (vaultoption == 1)
                {
                    print_records(&vault, vaultlen);
                }
                else if (vaultoption == 2)
                {
                    puts("Please provide a username, password, website's url, and rank number (rate how often you visit the website on a scale from 1-10) in the order stated.");
                    scanf("%s", username);
                    scanf("%s", password);
                    scanf("%s", website);
                    scanf("%d", &rank);
                    if (add_record(&vault, &vaultlen, userfile, username, password, website, rank))
                    {
                        puts("Record was successfully added.");
                    }
                    else
                    {
                        puts("Unable to add record.");
                    }
                }
                else if (vaultoption == 3)
                {
                    puts("Please provide the record's previous username, previous password, new username, new password, new url, and new rank number in the order stated.");
                    scanf("%s", username);
                    scanf("%s", password);
                    scanf("%s", newusername);
                    scanf("%s", newpassword);
                    scanf("%s", website);
                    scanf("%d", &rank);
                    if (modify_record(&vault, &vaultlen, userfile, username, password, newusername, newpassword, website, rank))
                    {
                        puts("Record was successfully updated.");
                    }
                    else
                    {
                        puts("Unable to update record.");
                    }
                }
                else if (vaultoption == 4)
                {
                    puts("Please provide the record's username and password in the order stated.");
                    scanf("%s", username);
                    scanf("%s", password);
                    if (delete_record(&vault, &vaultlen, userfile, username, password))
                    {
                        puts("Record was successfully deleted.");
                    }
                    else
                    {
                        puts("Unable to delete record.");
                    }
                }
                else if (vaultoption == 5)
                {
                    if (remove(userfile) == 0)
                    {
                        printf("File [%s] has been successfully deleted.\n", userfile);
                        if (vaultlen != 0)
                        {
                            free(vault);
                        }
                        vaultlen = 0;
                    }
                    else
                    {
                        perror("Error deleting user's personal file");
                    }
                }
                else if (vaultoption == 6)
                {
                    if (vaultlen != 0)
                    {
                        free(vault);
                    }
                    break;
                }
                else if (vaultoption == 7)
                {
                    if (vaultlen != 0)
                    {
                        free(vault);
                    }
                    unload();
                    return 0;
                }
                else
                {
                    while (getchar() != '\n');
                    puts("Invalid input! Please select either of the options numbered from 1-7.");
                }
            }
        }
        else if (option == 2)
        {
            int temp = 0;
            puts("Please enter a username that contains 6 - 20 valid characters:");
            scanf("%s", masterusername);
            puts("Please enter a password that contains a mixture of upper/lowercase letters, numbers, and symbols.");
            puts("If you would like a random password to be generated for you, select 2. Otherwise, select 1 to create your own.");
            scanf("%d", &temp);
            if (temp == 1)
            {
                puts("Enter a valid password that contains 12 - 20 valid characters:");
                scanf("%s", masterpassword);
            }
            else if (temp == 2)
            {
                gen_randpassword(masterpassword, MPASSWORDSIZE);
                printf("Your generated password is: %s\n", masterpassword);
            }
            else
            {
                printf("[%d] is an invalid input. Try again.\n", temp);
                continue;
            }
            if (!create_account(argv[1], argv[2], masterusername, masterpassword))
            {
                puts("Account couldn't be created. Please try again.");
            }
            else
            {
                puts("Account was successfully created.");
            }
        }
        else if (option == 3)
        {
            char newmasteru[MUSERNAMESIZE + 1] = {0};
            char newmasterp[MPASSWORDSIZE + 1] = {0};
            puts("Enter your current username: ");
            scanf("%s", masterusername);
            puts("Enter your current password: ");
            scanf("%s", masterpassword);
            puts("Enter your new username: ");
            scanf("%s", newmasteru);
            puts("Enter your new password: ");
            scanf("%s", newmasterp);
            if (modify_account(argv[1], argv[2], masterusername, masterpassword, newmasteru, newmasterp))
            {
                puts("Account information successfully changed");
            }
            else
            {
                puts("Failed to update account information.");
            }
        }
        else if (option == 4)
        {
            char i;
            puts("Are you sure you want to proceed with deleting your master account and vault. This action is irreversible. Select Y to continue or N to discontinue.");
            scanf(" %c", &i);
            if (i == 'N' || i == 'n')
            {
                puts("Action wasn't completed.");
                continue;
            }
            else if (i != 'Y' && i != 'y')
            {
                puts("Invalid input. Please enter 'Y' or 'N'.");
                continue;
            }
            puts("Enter your username");
            scanf("%s", masterusername);
            puts("Enter your password");
            scanf("%s", masterpassword);
            if (!delete_account(argv[1], argv[2], masterusername, masterpassword))
            {
                puts("Unable to successfully delete account.");
            }
            else
            {
                puts("Account was successfully deleted.");
            }
        }
        else if (option == 5)
        {
            unload();
            return 0;
        }
        else
        {
            while (getchar() != '\n');
            puts("Invalid input! Please select either of the options numbered from 1-5.");
        }
    }
    return 0;
}