#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <regex.h>
#define MPASSWORDSIZE 20
#define MUSERNAMESIZE 20
#define URLSIZE 20
#define MOD 101
#define P 89

typedef struct node
{
    char masteru[MUSERNAMESIZE + 1];
    char masterp[MPASSWORDSIZE + 1];
    struct node *next;
}
node;

typedef struct record
{
    char username[MUSERNAMESIZE + 1];
    char password[MPASSWORDSIZE + 1];
    char website[URLSIZE + 1];
    int rank;
}
record;

void gen_key_candidates();
void gen_xor_key(const char* user_password, char* key);
void xor_cipher(const char *input, char *output, const char *key);
void printRow(const char* username, const char* password, const char* website, char* rank, int columnWidths[]);
void printSeparator(int columnWidths[]);
void print_records(record **vault, int len);
bool insertion_sort(record **vault, int len);
bool delete_record(record **vault, int *len, const char *userfile, const char *username, const char *password);
bool modify_record(record **vault, int *len, const char *userfile, const char *prevusername, const char *prevpassword, const char *newusername, const char *newpassword, const char *website, int rank);
bool add_record(record **vault, int *len, const char *userfile, const char *username, const char *password, const char *website, int rank);
bool is_valid_recordusername(record **vault, const char *rusername, int len);
bool is_valid_recordpassword(record **vault, const char *password, int len);
bool load_vault(const char *userfile, record **vault, int *len);
bool get_password(char *password, char *encryptedpassword, const char *musername, const char *accountkeys);
bool is_strong_password(const char *password, int len);
void gen_randpassword(char *buffer, int length);
unsigned int hashindex(const char *username);
bool open_userfile(char* userfile, const char *musername);
bool account_exists(const char *musername, const char *mpassword, const char *accountkeys);
bool update_userfile(const char *file, const char *target1, const char *target2, const char *replacement1, const char *replacement2, bool do_rename);
bool create_account(const char *datafile, const char *accountkeys, const char *musername, const char *mpassword);
bool delete_account(const char *datafile, const char *accountkeys, const char *musername, const char *mpassword);
bool modify_account(const char *datafile, const char *accountkeys, const char *prevusername, const char *prevpassword, const char *newusername, const char *newpassword);
bool is_valid_mpassword(const char *password, const char *accountkeys, const char *username);
bool is_valid_musername(const char *username);
bool is_valid_username(const char *username);
bool is_valid_password(const char *password);
bool load_accounts(const char *accounts, const char *accountkeys);
bool unload(void);
void free_row(node *node);