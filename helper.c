#include "helper.h"

// Number of buckets in hash table
const unsigned int N = MOD;
const int DATA_BLOCK_SIZE = MUSERNAMESIZE + MPASSWORDSIZE + 3;
const int RECORD_BLOCK_SIZE = MUSERNAMESIZE + MPASSWORDSIZE + URLSIZE + 5;

// Hash table
node *table[N];

bool gen_valid_key(const char *input, char *output, char *key)
{
    char tempinput[MPASSWORDSIZE + 1] = {0};
    strcpy(tempinput, input);
    int length = strlen(tempinput);
    do
    {
        while (!gen_key(key, length));
        xor_cipher(tempinput, output, key);
    }
    while (!is_valid_encryption(output));
    xor_cipher(output, tempinput, key);
    if (strcasecmp(tempinput, input) != 0)
    {
        return false;
    }
    return true;
}

bool is_valid_encryption(char *input)
{
    int len = strlen(input);
    for (int i = 0; i < len; i++)
    {
        int charValue = input[i];
        if ((charValue >= 0 && charValue <= 32) || charValue == 127)
        {
            return false;
        }
    }
    for (int i = len; i < MPASSWORDSIZE + 1; i++)
    {
        int charValue = input[i];
        if (charValue != '\0')
        {
            return false;
        }
    }
    return true;
}

void xor_cipher(const char *input, char *output, const char *key)
{
    int length = strlen(input);
	for(int i = 0; i < length; i++)
	{
		output[i] = input[i] ^ key[i];
	}
	output[length] = '\0';
}

bool gen_key(char *key, int len)
{
	char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int size = sizeof(charset) - 1;
	for (int index = 0; index < len; index++)
	{
		key[index] = charset[rand() % size];
        if (key[index] == '\0') return false;
	}
    key[len] = '\0';
    return true;
}

bool delete_record(record **vault, int *len, const char *userfile, const char *username, const char *password)
{
    for (int i = 0; i < *len; i++)
    {
        if (strcasecmp((*vault)[i].username, username) == 0 && strcasecmp((*vault)[i].password, password) == 0)
        {
            record* newVault = (record*)malloc(sizeof(record) * (--(*len)));
            if (newVault == NULL)
            {
                printf("Unable to allocate memory for new vault.");
                (*len)++;
                return false;
            }
            FILE *fvaultu = fopen(userfile, "w");
            if (fvaultu == NULL)
            {
                free(*vault);
                (*len) = 0;
                printf("Unable to open and update user file. Vault was emptied.\n");
                return false;
            }
            int indexToDelete = i;
            for (int j = 0; j < indexToDelete; j++)
            {
                strcpy(newVault[j].username, (*vault)[j].username);
                strcpy(newVault[j].password, (*vault)[j].password);
                strcpy(newVault[j].website, (*vault)[j].website);
                newVault[j].rank = (*vault)[j].rank;
            }
            for (int j = indexToDelete + 1; j <= *len; j++)
            {
                strcpy(newVault[j - 1].username, (*vault)[j].username);
                strcpy(newVault[j - 1].password, (*vault)[j].password);
                strcpy(newVault[j - 1].website, (*vault)[j].website);
                newVault[j - 1].rank = (*vault)[j].rank;
            }
            free(*vault);
            *vault = newVault;
            insertion_sort(&(*vault), *len);
            for (int index = 0; index < *len; index++)
            {
                fprintf(fvaultu, "%s %s %s %d\n", (*vault)[index].username, (*vault)[index].password, (*vault)[index].website, (*vault)[index].rank);
            }
            fclose(fvaultu);
            return true;
        }
    }
    return false;
}

bool modify_record(record **vault, int *len, const char *userfile, const char *prevusername, const char *prevpassword, const char *newusername, const char *newpassword, const char *website, int rank)
{
    if (!is_valid_recordpassword(&(*vault), newpassword, *len) || !is_valid_recordusername(&(*vault), newusername, *len))
    {
        return false;
    }
    int urllength = strlen(website);
    if (urllength < 0 || urllength > URLSIZE)
    {
        printf("Invalid URL size.\n");
        return false;
    }
    if (rank < 1 || rank > 10)
    {
        printf("Invalid rank number.\n");
        return false;
    }
    for (int i = 0; i < *len; i++)
    {
        if (strcasecmp((*vault)[i].username, prevusername) == 0 && strcasecmp((*vault)[i].password, prevpassword) == 0)
        {
            strcpy((*vault)[i].username, newusername);
            strcpy((*vault)[i].password, newpassword);
            strcpy((*vault)[i].website, website);
            (*vault)[i].rank = rank;
            FILE *fvaultu = fopen(userfile, "w");
            if (fvaultu == NULL)
            {
                free(*vault);
                (*len) = 0;
                printf("Unable to open and update user file. Vault was emptied.\n");
                return false;
            }
            insertion_sort(&(*vault), *len);
            for (int index = 0; index < *len; index++)
            {
                fprintf(fvaultu, "%s %s %s %d\n", (*vault)[index].username, (*vault)[index].password, (*vault)[index].website, (*vault)[index].rank);
            }
            fclose(fvaultu);
            return true;
        }
    }
    return false;
}


bool add_record(record **vault, int *len, const char *userfile, const char *username, const char *password, const char *website, int rank)
{
    if (!is_valid_recordpassword(&(*vault), password, *len) || !is_valid_recordusername(&(*vault), username, *len))
    {
        return false;
    }
    int urllength = strlen(website);
    if (urllength < 0 || urllength > URLSIZE)
    {
        printf("Invalid URL size.\n");
        return false;
    }
    if (rank < 1 || rank > 10)
    {
        printf("Invalid rank number.\n");
        return false;
    }
    record *temp = (record*)realloc(*vault, sizeof(record) * (++(*len)));
    if (temp == NULL)
    {
        printf("Unable to allocate memory for new record.\n");
        (*len)--;
        return false;
    }
    *vault = temp;
    strcpy((*vault)[(*len) - 1].username, username);
    strcpy((*vault)[(*len) - 1].password, password);
    strcpy((*vault)[(*len) - 1].website, website);
    (*vault)[(*len) - 1].rank = rank;
    FILE *fvaultu = fopen(userfile, "w");
    if (fvaultu == NULL)
    {
        free(*vault);
        (*len) = 0;
        printf("Unable to open and update user file. Vault was emptied.\n");
        return false;
    }
    insertion_sort(&(*vault), *len);
    for (int i = 0; i < *len; i++)
    {
        fprintf(fvaultu, "%s %s %s %d\n", (*vault)[i].username, (*vault)[i].password, (*vault)[i].website, (*vault)[i].rank);
    }
    fclose(fvaultu);
    return true;
}


bool is_valid_recordpassword(record **vault, const char *password, int len)
{
    if (!is_valid_password(password))
    {
        return false;
    }
    for (int i = 0; i < len; i++)
    {
        if (strcasecmp((*vault)[i].password, password) == 0)
        {
            printf("[%s] is a password that's already taken.\n", password);
            return false;
        }
    }
    return true;
}

bool is_valid_recordusername(record **vault, const char *rusername, int len)
{
    if (!is_valid_username(rusername))
    {
        return false;
    }
    for (int i = 0; i < len; i++)
    {
        if (strcasecmp((*vault)[i].username, rusername) == 0)
        {
            printf("[%s] is a username already taken.\n", rusername);
            return false;
        }
    }
    return true;
}

bool is_strong_password(const char *password, int len)
{
    int symbolCount = 0, numberCount = 0, uppercaseCount = 0, lowercaseCount = 0;
    for (int i = 0; i < len; i++)
    {
        if (isupper(password[i]))
        {
            uppercaseCount++;
        }
        else if (islower(password[i]))
        {
            lowercaseCount++;
        }
        else if (isdigit(password[i]))
        {
            numberCount++;
        }
        else
        {
            symbolCount++;
        }
    }
    if (symbolCount < 2 || numberCount < 2 || uppercaseCount < 3 || lowercaseCount < 3)
    {
        return false;
    }
    return true;
}

bool insertion_sort(record **vault, int len)
{
    for (int i = 1; i < len; i++)
    {
        record *key = (record*)malloc(sizeof(record));
        if (key == NULL)
        {
            printf("Unable to allocate memory for temp key. Sorting was unsuccessful.\n");
            return false;
        }
        strcpy(key->username, (*vault)[i].username);
        strcpy(key->password, (*vault)[i].password);
        strcpy(key->website, (*vault)[i].website);
        key->rank = (*vault)[i].rank;
        int j = i - 1;
        while (j >= 0 && (*vault)[j].rank < key->rank)
        {
            strcpy((*vault)[j + 1].username, (*vault)[j].username);
            strcpy((*vault)[j + 1].password, (*vault)[j].password);
            strcpy((*vault)[j + 1].website, (*vault)[j].website);
            (*vault)[j + 1].rank = (*vault)[j].rank;
            j--;
        }
        strcpy((*vault)[j + 1].username, key->username);
        strcpy((*vault)[j + 1].password, key->password);
        strcpy((*vault)[j + 1].website, key->website);
        (*vault)[j + 1].rank = key->rank;
        free(key);
    }
    return true;
}

void print_records(record **vault, int len)
{
    printf("Username:\tPassword:\t\tWebsite:\tRank:\n");
    for (int i = 0; i < len; i++)
    {
        printf("%s\t%s\t%s\t%d\n", (*vault)[i].username, (*vault)[i].password, (*vault)[i].website, (*vault)[i].rank);
    }
    printf("\n");
}

bool load_vault(const char *userfile, record **vault, int *vaultlen)
{
    FILE *fvault = fopen(userfile, "r");
    if (fvault == NULL)
    {
        printf("Unable to open user file.\n");
        return false;
    }
    char buffer[RECORD_BLOCK_SIZE];
    int col, row = -1;
    while (fgets(buffer, RECORD_BLOCK_SIZE, fvault) != NULL)
    {
        row++;
        col = 0;
        (*vaultlen)++;
        if (row == 0)
        {
            *vault = (record*)malloc(sizeof(record));
            if (*vault == NULL)
            {
                fclose(fvault);
                printf("Memory not available to load initial record in vault.\n");
                (*vaultlen) = 0;
                return false;
            }
        }
        else
        {
            record *temp = (record*)realloc(*vault, sizeof(record) * (*vaultlen));
            if (temp == NULL)
            {
                fclose(fvault);
                free(*vault); // when doing this the vault len has to be reset to 0 and then you're done
                (*vaultlen) = 0;
                printf("Memory not available to load all records in vault.\n");
                return false;
            }
            *vault = temp;
        }
        char delimit[] = " \n";
        char *word = strtok(buffer, delimit);
        while (word != NULL)
        {
            if (col == 0)
            {
                if (!is_valid_recordusername(&(*vault), word, (*vaultlen) - 1))
                {
                    free(*vault);
                    (*vaultlen) = 0;
                    fclose(fvault);
                    return false;
                }
                strcpy((*vault)[(*vaultlen) - 1].username, word);
            }
            if (col == 1)
            {
                if (!is_valid_recordpassword(&(*vault), word, ((*vaultlen) - 1)))
                {
                    free(*vault);
                    (*vaultlen) = 0;
                    fclose(fvault);
                    return false;
                }
                strcpy((*vault)[(*vaultlen) - 1].password, word);
            }
            if (col == 2)
            {
                int urllength = strlen(word);
                if (urllength < 0 || urllength > URLSIZE)
                {
                    printf("[%s] contains an invalid URL size.\n", (*vault)[(*vaultlen) - 1].username);
                    free(*vault);
                    (*vaultlen) = 0;
                    fclose(fvault);
                    return false;
                }
                strcpy((*vault)[(*vaultlen) - 1].website, word);
            }
            if (col == 3)
            {
                int rank = atoi(word);
                if (rank < 1 || rank > 10)
                {
                    printf("[%s] contains an invalid rank number.\n", (*vault)[(*vaultlen) - 1].username);
                    free(*vault);
                    (*vaultlen) = 0;
                    fclose(fvault);
                    return false;
                }
                (*vault)[(*vaultlen) - 1].rank = rank;
            }
            word = strtok(NULL, delimit);
            col++;
        }
    }
    fclose(fvault);
    FILE *fvaultu = fopen(userfile, "w");
    if (fvaultu == NULL)
    {
        free(*vault);
        (*vaultlen) = 0;
        printf("User file has been cleared. Vault couldn't be loaded properly.\n");
        return false;
    }
    insertion_sort(&(*vault), (*vaultlen));
    for (int i = 0; i < *vaultlen; i++)
    {
        fprintf(fvaultu, "%s %s %s %d\n", (*vault)[i].username, (*vault)[i].password, (*vault)[i].website, (*vault)[i].rank);
    }
    fclose(fvaultu);
    return true;
}


bool open_userfile(char *userfile, const char *musername)
{
    if (sprintf(userfile, "%s.txt", musername) < 0)
    {
        return false;
    }
    FILE *fusrfile = fopen(userfile, "a");
    if (fusrfile == NULL)
    {
        return false;
    }
    fclose(fusrfile);
    return true;
}

bool account_exists(const char *musername, const char *mpassword, const char *accountkeys)
{
    char password[MPASSWORDSIZE + 1] = {0};
    int i = hashindex(musername);
    node *temp = table[i];
    while (temp != NULL)
    {
        get_password(password, temp->masterp, musername, accountkeys);
        if (strcasecmp(temp->masteru, musername) == 0 && strcasecmp(password, mpassword) == 0)
        {
            return true;
        }
        temp = temp->next;
    }
    return false;
}

void gen_randpassword(char *buffer, int length)
{
    bool flag = false;
    while (flag == false)
    {
        flag = true;
        char validchars[] = "a0!Cq\"b#Arc$%PB&Op2Q'D(SmR*E)nT3dw+5,oUFv-fG.I4/:lV;eWHuk<=X>6?g@sYZ[\\J7]tL^_K1`{|8hi}~MyNxj9z";
        int max = sizeof(validchars) - 1, min = 0;
        for (int i = 0; i < length; i++)
        {
            buffer[i] = validchars[rand() % (max + 1 - min) + min];
        }
        buffer[length] = '\0';
        if (!is_strong_password(buffer, length))
        {
            flag = false;
        }
    }
}
bool update_userfile(const char *file, const char *target1, const char *target2, const char *replacement1, const char *replacement2, bool do_rename)
{
    FILE *fuserfile = fopen(file, "r");
    if (fuserfile == NULL)
    {
        printf("Error opening [%s] file.\n", file);
        return false;
    }
    FILE *tempFile = fopen("temp.txt", "w");
    if (tempFile == NULL)
    {
        printf("Error opening temp file\n");
        return false;
    }
    char buffer[DATA_BLOCK_SIZE];
    char lineToRemove[DATA_BLOCK_SIZE + 1] = {0};
    strcat(lineToRemove, target1);
    strcat(lineToRemove, " ");
    strcat(lineToRemove, target2);
    strcat(lineToRemove, "\n");
    bool found = false;
    while (fgets(buffer, DATA_BLOCK_SIZE, fuserfile)) {
        int count = -1;
        int nplace = 0;
        for (int i = 0; i < DATA_BLOCK_SIZE; i++)
        {
            if (buffer[i] == ' ')
            {
                count++;
            }
            if (count == 1)
            {
                nplace = i;
                break;
            }
        }
        if (count > 0)
        {
            buffer[nplace] = '\n';
            buffer[nplace + 1] = '\0';
        }
        if (strcmp(buffer, lineToRemove) != 0)
        {
            fputs(buffer, tempFile);
        }
        else
        {
             found = true;
        }
    }
    fclose(fuserfile);
    fclose(tempFile);
    if (!found)
    {
        printf("Unsuccessful in locating line to remove.\n");
        return false;
    }
    if (remove(file) != 0)
    {
        printf("Error deleting [%s] file.\n", file);
        return false;
    }
    if (rename("temp.txt", file) != 0)
    {
        printf("Error renaming temp file.\n");
        return false;
    }
    if (!do_rename)
    {
        return true;
    }
    FILE *fpuserfile = fopen(file, "a");
    if (fpuserfile == NULL)
    {
        printf("Error in reopening [%s] file to update\n", file);
        return false;
    }
    fprintf(fpuserfile, "%s %s\n", replacement1, replacement2);
    fclose(fpuserfile);
    return true;
}

bool modify_account(const char *datafile, const char *accountkeys, const char *prevusername, const char *prevpassword, const char *newusername, const char *newpassword)
{
    if (!is_valid_musername(newusername) || !is_valid_mpassword(newpassword, accountkeys))
    {
        return false;
    }
    char password[MPASSWORDSIZE + 1] = {0};
    int i = hashindex(prevusername);
    node *temp = table[i];
    node *prev = table[i];
    int count = 0;
    while (temp != NULL)
    {
        get_password(password, temp->masterp, prevusername, accountkeys);
        if (strcasecmp(temp->masteru, prevusername) == 0 && strcasecmp(password, prevpassword) == 0)
        {
            node *account = (node*)malloc(sizeof(node));
            if (account == NULL)
            {
                printf("Unable to allocate memory for altered account.");
                return false;
            }
            char oldFileName[MUSERNAMESIZE + 5] = {0};
            char newFileName[MUSERNAMESIZE + 5] = {0};
            if (sprintf(oldFileName, "%s.txt", prevusername) < 0)
            {
                printf("Error in determining old filename.\n");
                return false;
            }
            if (sprintf(newFileName, "%s.txt", newusername) < 0)
            {
                printf("Error in determining new filename\n");
            }
            if (rename(oldFileName, newFileName) != 0)
            {
                printf("Error renaming account's personal file.\n");
                return false;
            }
            int newindex = hashindex(newusername);
            account->next = table[newindex];
            table[newindex] = account;
            char encryptedpassword[MPASSWORDSIZE + 1] = {0};
            char newkey[MPASSWORDSIZE + 1] = {0};
            while (1)
            {
                if (gen_valid_key(newpassword, encryptedpassword, newkey)) break;
            }
            strcpy(account->masteru, newusername);
            strcpy(account->masterp, encryptedpassword);
            char oldkey[MPASSWORDSIZE + 1] = {0};
            xor_cipher(temp->masterp, oldkey, prevpassword);
            if (!update_userfile(datafile, prevusername, temp->masterp, newusername, encryptedpassword, true))
            {
                return false;
            }
            if (!update_userfile(accountkeys, prevusername, oldkey, newusername, newkey, true))
            {
                return false;
            }
            if (table[i] == temp)
            {
                free(temp);
                table[i] = NULL;
            }
            else
            {
                prev->next = temp->next;
                free(temp);
            }
            return true;
        }
        temp = temp->next;
        count++;
        if (count > 1)
        {
            prev = prev->next;
        }
    }
    printf("Login info provided couldn't be matched to an existing account.\n");
    return false;
}

bool delete_account(const char *datafile, const char *accountkeys, const char *musername, const char *mpassword)
{
    char userfile[MUSERNAMESIZE + 5] = {0};
    char password[MPASSWORDSIZE + 1] = {0};
    int i = hashindex(musername);
    node *temp = table[i];
    node *prev = table[i];
    int count = 0;
    while (temp != NULL)
    {
        get_password(password, temp->masterp, musername, accountkeys);
        if (strcasecmp(temp->masteru, musername) == 0 && strcasecmp(password, mpassword) == 0)
        {
            if (sprintf(userfile, "%s.txt", musername) < 0)
            {
                printf("Error retreiving user's personal filename\n");
                return false;
            }
            if (remove(userfile) == 0)
            {
                printf("File [%s] deleted successfully.\n", userfile);
            }
            else
            {
                perror("Error deleting user's vault");
            }
            char oldkey[MPASSWORDSIZE + 1] = {0};
            xor_cipher(temp->masterp, oldkey, mpassword);
            if (!update_userfile(datafile, musername, temp->masterp, "", "", false))
            {
                return false;
            }
            if (!update_userfile(accountkeys, musername, oldkey, "", "", false))
            {
                return false;
            }
            if (table[i] == temp)
            {
                free(temp);
                table[i] = NULL;
            }
            else
            {
                prev->next = temp->next;
                free(temp);
            }
            return true;
        }
        temp = temp->next;
        count++;
        if (count > 1)
        {
            prev = prev->next;
        }
    }
    return false;
}

bool create_account(const char *datafile, const char *accountkeys, const char *musername, const char *mpassword)
{
    FILE *fpdata = fopen(datafile, "a");
    if (fpdata == NULL)
    {
        printf("Unable to create new master account.\n");
        return false;
    }
    FILE *fpkeys = fopen(accountkeys, "a");
    if (fpkeys == NULL)
    {
        printf("Unable to access key file.\n");
        fclose(fpdata);
        return false;
    }
    if (!is_valid_musername(musername) || !is_valid_mpassword(mpassword, accountkeys))
    {
        return false;
    }
    node *account = (node*)malloc(sizeof(node));
    if (account == NULL)
    {
        printf("Unable to allocate memory for altered account.");
        return false;
    }
    int i = hashindex(musername);
    account->next = table[i];
    table[i] = account;
    char encryptedpassword[MPASSWORDSIZE + 1] = {0};
    char key[MPASSWORDSIZE + 1] = {0};
    while (1)
    {
        if (gen_valid_key(mpassword, encryptedpassword, key)) break;
    }
    strcpy(account->masteru, musername);
    strcpy(account->masterp, encryptedpassword);
    fprintf(fpkeys, "%s %s\n", account->masteru, key);
    fprintf(fpdata, "%s %s\n", account->masteru, account->masterp);
    fclose(fpkeys);
    fclose(fpdata);
    return true;
}
// reserved for admin to display the encrypted login credentials of user accounts
void read_datafile(void)
{
    printf("Username:\tPassword:\n");
    for (int i = 0; i < N; i++)
    {
        node *temp = table[i];
        while (temp != NULL)
        {
            printf("%s\t%s\n", temp->masteru, temp->masterp);
            temp = temp->next;
        }
    }
    printf("\n");
}

void free_row(node *node)
{
    // if we have passed the last node
    if (node == NULL)
    {
        return; // return to start freeing allocated memory starting backward from the last node
    }
    free_row(node->next);
    free(node);
}

bool unload(void)
{
    // for the current table's "row" of nodes
    for (int i = 0; i < N; i++)
    {
        free_row(table[i]); // free the allocated memory used for the nodes in the "row"
        // if we have freed all the rows sucessfully, then return true to show this
        if (i == N - 1)
        {
            return true;
        }
    }
    return false; // return false to show allocated memory wasn't sucessfully freed
}

unsigned int hashindex(const char *username)
{
    unsigned int hashValue = 0, p_power = 1, charValue;
    char validchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'(*)+,-./:;<=>?@[\\]^_`{|}~";
    int length = strlen(username), numValidChars = sizeof(validchars) - 1; // 94
    for (int i = 0; i < length; i++)
    {
        charValue = 0;
        for (int j = 0; j < numValidChars; j++)
        {
            if (username[i] == validchars[j])
            {
                charValue = j + 1;
                break;
            }
        }
        hashValue = (hashValue + (charValue * p_power)) % MOD;
        p_power = (P * p_power) % MOD;
    }
    return hashValue;
}

bool is_valid_password(const char *password)
{
    int length = strlen(password);
    if (length < 12 || length > MPASSWORDSIZE)
    {
        printf("[%s] is an invalid password length of %d. Enter a password that contains 12-20 valid characters.\n", password, length);
        return false;
    }
    int retval;
    regex_t regex;
    retval = regcomp(&regex, "[^A-Za-z0-9!\"#$%&'(*)+,-./:;<=>?@[\\]^_`{|}~]", 0);
    if (retval != 0)
    {
        printf("Regex compiled unsucessfully.\n");
        regfree(&regex);
        return false;
    }
    retval = regexec(&regex, password, 0, NULL, 0);
    if (retval == 0)
    {
        printf("[%s] contains invalid characters.\n", password);
        regfree(&regex);
        return false;
    }
    else if (retval != 0 && retval != REG_NOMATCH)
    {
        printf("Error ocurred during regex pattern matching.\n");
        regfree(&regex);
        return false;
    }
    regfree(&regex);
    if (!is_strong_password(password, length))
    {
        printf("[%s] is a weak password. Create a stronger password.\n", password);
        return false;
    }
    return true;
}

bool is_valid_mpassword(const char *password, const char *accountkeys)
{
    if (!is_valid_password(password))
    {
        return false;
    }
    char mpassword[MPASSWORDSIZE + 1] = {0};
    for (int i = 0; i < N; i++)
    {
        node *temp = table[i];
        while (temp != NULL)
        {
            get_password(mpassword, temp->masterp, temp->masteru, accountkeys);
            if (strcasecmp(mpassword, password) == 0)
            {
                printf("[%s] is a password that's already taken.\n", password);
                return false;
            }
            temp = temp->next;
        }
    }
    return true;
}

bool is_valid_username(const char *username)
{
    int length = strlen(username);
    if (length < 6 || length > MUSERNAMESIZE)
    {
        printf("[%s] contains an invalid username length of %d. Enter a username that contains 6-20 valid characters.\n", username, length);
        return false;
    }
    int retval;
    regex_t regex;
    retval = regcomp(&regex, "[^A-Za-z0-9_]", 0);
    if (retval != 0)
    {
        printf("Regex compiled unsucessfully.\n");
        regfree(&regex);
        return false;
    }
    retval = regexec(&regex, username, 0, NULL, 0);
    if (retval == 0)
    {
        printf("[%s] contains invalid characters.\n", username);
        regfree(&regex);
        return false;
    }
    else if (retval != 0 && retval != REG_NOMATCH)
    {
        printf("Error ocurred during regex pattern matching.\n");
        regfree(&regex);
        return false;
    }
    regfree(&regex);
    return true;
}

bool is_valid_musername(const char *username)
{
    if (!is_valid_username(username))
    {
        return false;
    }
    int index = hashindex(username);
    node *temp = table[index];
    while (temp != NULL)
    {
        if (strcasecmp(temp->masteru, username) == 0)
        {
            printf("[%s] already exists.\n", username);
            return false;
        }
        temp = temp->next;
    }
    return true;
}

bool load_accounts(const char *accounts, const char *accountkeys)
{
    for (int i = 0; i < N; i++)
    {
        table[i] = NULL;
    }
    FILE *fprdata = fopen(accounts, "r");
    if (fprdata == NULL)
    {
        printf("Data file couldn't be opened\n");
        return false;
    }
    char buffer[DATA_BLOCK_SIZE];
    int col, i;
    while (fgets(buffer, DATA_BLOCK_SIZE, fprdata) != NULL)
    {
        col = 0;
        node *account = (node*)malloc(sizeof(node));
        if (account == NULL)
        {
            unload();
            fclose(fprdata);
            return false;
        }
        account->next = NULL;
        char delimit[] = " \n";
        char *word = strtok(buffer, delimit);
        while (word != NULL)
        {
            if (col == 0)
            {
                if (!is_valid_musername(word))
                {
                    unload();
                    fclose(fprdata);
                    return false;
                }
                strcpy(account->masteru, word);
            }
            if (col == 1)
            {
                char password[MPASSWORDSIZE + 1] = {0};
                if (!get_password(password, word, account->masteru, accountkeys))
                {
                    unload();
                    fclose(fprdata);
                    return false;
                }
                if (!is_valid_mpassword(password, accountkeys))
                {
                    unload();
                    fclose(fprdata);
                    return false;
                }
                strcpy(account->masterp, word);
            }
            word = strtok(NULL, delimit);
            col++;
        }
        i = hashindex(account->masteru);
        account->next = table[i]; // prepend for O(1) insertion time
        table[i] = account;
    }
    fclose(fprdata);
    return true;
}

bool get_password(char *password, char *encryptedpassword, const char *musername, const char *accountkeys)
{
    FILE *fkeys = fopen(accountkeys, "r");
    if (fkeys == NULL)
    {
        fclose(fkeys);
        return false;
    }
    char buffer[DATA_BLOCK_SIZE];
    int col;
    while (fgets(buffer, DATA_BLOCK_SIZE, fkeys) != NULL)
    {
        col = 0;
        char delimit[] = " \n";
        char *word = strtok(buffer, delimit);
        char tempusername[MUSERNAMESIZE + 1] = {0};
        while (word != NULL)
        {
            if (col == 0)
            {
                strcpy(tempusername, word);
            }
            else if (col == 1)
            {
                if (strcasecmp(musername, tempusername) == 0)
                {
                    xor_cipher(encryptedpassword, password, word);
                    fclose(fkeys);
                    return true;
                }
            }
            word = strtok(NULL, delimit);
            col++;
        }
    }
    fclose(fkeys);
    return false;
}
