/*
 * Bank Management System
 * Created by: Chiranjivi R
 *
 * Features:
 * - Manager login with hashed password authentication (SHA-256)
 * - Customer account management with safe binary storage
 * - Dynamic transaction array per account backed by a single transactions log
 * - Safe file operations with comprehensive error handling
 * - Safe input functions (no unsafe scanf/gets)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#define SALT_SIZE 16
#define HASH_SIZE 32
#define MAX_NAME_LEN 100
#define MAX_ID_LEN 100
#define MAX_PASS_LEN 100
#define INITIAL_CAPACITY 10
#define MAX_TYPE_LEN 20
#define BANK_FILE "BankAcc.dat"
#define MANAGER_FILE "Manager.dat"
#define TEMP_FILE "temp.dat"
#define TRANSACTION_FILE "transactions.dat"

struct transaction {
    char type[MAX_TYPE_LEN + 1];
    int amount;
    time_t timestamp;
};

struct TransactionArray {
    struct transaction *data;
    int size;
    int capacity;
};

struct account {
    int num;
    int pin;
    int balance;
    char name[MAX_NAME_LEN + 1];
    struct TransactionArray trans;
};

typedef enum {
    ACCOUNT_READ_OK,
    ACCOUNT_READ_EOF,
    ACCOUNT_READ_ERROR
} AccountReadStatus;

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void clearInputBuffer(void);
void getLine(char *buffer, size_t size);
void getPassword(char *buffer, size_t size);
bool promptMaskedPin(int *pinValue);
int getInt(void);
void initArray(struct TransactionArray *arr);
void resizeArray(struct TransactionArray *arr);
void addTransaction(struct TransactionArray *arr, struct transaction trans);
void freeArray(struct TransactionArray *arr);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
void hash_password(const unsigned char *salt, const char *password, unsigned char output[HASH_SIZE]);
void hash_pin_value(int pinValue, unsigned char output[HASH_SIZE]);
AccountReadStatus readAccount(FILE *fp, struct account *acc);
bool writeAccount(FILE *fp, const struct account *acc);
bool updateAccountRecord(const struct account *updated);
bool loadTransactionsForAccount(int accountNumber, struct TransactionArray *arr);
bool appendTransactionRecord(int accountNumber, const char *type, int amount, time_t timestamp);
bool loadAccountByCredentials(int accNum, int pin, struct account *result);
void ensureBankFileExists(void);
void ensureTransactionFileExists(void);
int managerLogin(void);
void list(void);
void search(void);
void add(void);
void modify(void);
void deleteAccount(void);
void manager(void);
int deposit(struct account *acc);
int withdraw(struct account *acc);
void details(struct account *acc, int pointer);
void customer(void);

void clearInputBuffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        /* discard */
    }
}

void getLine(char *buffer, size_t size) {
    if (fgets(buffer, (int)size, stdin) == NULL) {
        buffer[0] = '\0';
        return;
    }

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
}

static int readHiddenChar(void) {
#ifdef _WIN32
    return _getch();
#else
    struct termios oldt, newt;
    int ch;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        return getchar();
    }
    newt = oldt;
    newt.c_lflag &= (unsigned int)~(ICANON | ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        return getchar();
    }
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
#endif
}

void getPassword(char *buffer, size_t size) {
    size_t idx = 0;
    int ch;

    if (size == 0) {
        return;
    }

    while (1) {
        ch = readHiddenChar();
        if (ch == '\r' || ch == '\n') {
            break;
        } else if ((ch == '\b' || ch == 127)) {
            if (idx > 0) {
                idx--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (ch == EOF) {
            break;
        } else if (isprint(ch)) {
            if (idx < size - 1) {
                buffer[idx++] = (char)ch;
                printf("*");
                fflush(stdout);
            }
        }
    }

    buffer[idx] = '\0';
    printf("\n");
}

bool promptMaskedPin(int *pinValue) {
    char input[32];
    size_t i, length;
    long value;
    char *endptr;
    bool digitsOnly;

    if (pinValue == NULL) {
        return false;
    }

    while (1) {
        printf("Enter pin: ");
        getPassword(input, sizeof(input));

        length = strlen(input);
        if (length == 0) {
            printf("PIN cannot be empty.\n");
            continue;
        }

        digitsOnly = true;
        for (i = 0; i < length; i++) {
            if (!isdigit((unsigned char)input[i])) {
                digitsOnly = false;
                break;
            }
        }

        if (!digitsOnly) {
            printf("PIN must contain digits only.\n");
            continue;
        }

        errno = 0;
        value = strtol(input, &endptr, 10);
        if (errno != 0 || endptr == input || *endptr != '\0' || value < 0 || value > INT_MAX) {
            printf("Invalid PIN. Please try again.\n");
            continue;
        }

        *pinValue = (int)value;
        return true;
    }
}

int getInt(void) {
    char input[128];
    long value;
    char *endptr;

    while (1) {
        if (fgets(input, sizeof(input), stdin) == NULL) {
            return 0;
        }

        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }

        errno = 0;
        value = strtol(input, &endptr, 10);
        if (errno == 0 && endptr != input && *endptr == '\0' && value >= INT_MIN && value <= INT_MAX) {
            return (int)value;
        }

        printf("Invalid input. Please enter a valid number: ");
    }
}

void initArray(struct TransactionArray *arr) {
    arr->data = (struct transaction *)malloc(INITIAL_CAPACITY * sizeof(struct transaction));
    if (arr->data == NULL) {
        printf("Error: Memory allocation failed.\n");
        exit(1);
    }
    arr->size = 0;
    arr->capacity = INITIAL_CAPACITY;
}

void resizeArray(struct TransactionArray *arr) {
    int newCapacity = arr->capacity * 2;
    struct transaction *temp = (struct transaction *)realloc(arr->data, newCapacity * sizeof(struct transaction));
    if (temp == NULL) {
        printf("Error: Memory reallocation failed.\n");
        freeArray(arr);
        exit(1);
    }
    arr->data = temp;
    arr->capacity = newCapacity;
}

void addTransaction(struct TransactionArray *arr, struct transaction trans) {
    if (arr->data == NULL) {
        initArray(arr);
    }

    if (arr->size >= arr->capacity) {
        resizeArray(arr);
    }

    arr->data[arr->size] = trans;
    arr->size++;
}

void freeArray(struct TransactionArray *arr) {
    if (arr->data != NULL) {
        free(arr->data);
        arr->data = NULL;
    }
    arr->size = 0;
    arr->capacity = 0;
}

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t m[64];
    int i;

    for (i = 0; i < 16; ++i) {
        m[i] = (uint32_t)data[i * 4] << 24;
        m[i] |= (uint32_t)data[i * 4 + 1] << 16;
        m[i] |= (uint32_t)data[i * 4 + 2] << 8;
        m[i] |= (uint32_t)data[i * 4 + 3];
    }

    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    size_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i;

    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

void hash_password(const unsigned char *salt, const char *password, unsigned char output[HASH_SIZE]) {
    unsigned char buffer[SALT_SIZE + MAX_PASS_LEN];
    size_t pass_len = strlen(password);

    if (pass_len > MAX_PASS_LEN) {
        pass_len = MAX_PASS_LEN;
    }

    memcpy(buffer, salt, SALT_SIZE);
    memcpy(buffer + SALT_SIZE, password, pass_len);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, buffer, SALT_SIZE + pass_len);
    sha256_final(&ctx, output);
}

void hash_pin_value(int pinValue, unsigned char output[HASH_SIZE]) {
    char buffer[32];
    size_t len;

    snprintf(buffer, sizeof(buffer), "%d", pinValue);
    len = strlen(buffer);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)buffer, len);
    sha256_final(&ctx, output);
}

AccountReadStatus readAccount(FILE *fp, struct account *acc) {
    int name_len;

    if (fread(&acc->num, sizeof(int), 1, fp) != 1) {
        if (feof(fp)) {
            return ACCOUNT_READ_EOF;
        }
        return ACCOUNT_READ_ERROR;
    }

    if (fread(&acc->pin, sizeof(int), 1, fp) != 1) return ACCOUNT_READ_ERROR;
    if (fread(&acc->balance, sizeof(int), 1, fp) != 1) return ACCOUNT_READ_ERROR;
    if (fread(&name_len, sizeof(int), 1, fp) != 1) return ACCOUNT_READ_ERROR;

    if (name_len < 0 || name_len > MAX_NAME_LEN) {
        return ACCOUNT_READ_ERROR;
    }

    if (fread(acc->name, sizeof(char), (size_t)name_len, fp) != (size_t)name_len) {
        return ACCOUNT_READ_ERROR;
    }
    acc->name[name_len] = '\0';

    acc->trans.data = NULL;
    acc->trans.size = 0;
    acc->trans.capacity = 0;

    return ACCOUNT_READ_OK;
}

bool writeAccount(FILE *fp, const struct account *acc) {
    int name_len = (int)strlen(acc->name);

    if (name_len < 0 || name_len > MAX_NAME_LEN) {
        printf("\nError: Invalid account name length.\n");
        return false;
    }

    if (fwrite(&acc->num, sizeof(int), 1, fp) != 1) return false;
    if (fwrite(&acc->pin, sizeof(int), 1, fp) != 1) return false;
    if (fwrite(&acc->balance, sizeof(int), 1, fp) != 1) return false;
    if (fwrite(&name_len, sizeof(int), 1, fp) != 1) return false;
    if (fwrite(acc->name, sizeof(char), (size_t)name_len, fp) != (size_t)name_len) return false;

    return true;
}

bool loadTransactionsForAccount(int accountNumber, struct TransactionArray *arr) {
    FILE *fp;
    int recordAccount;
    int type_len;
    struct transaction trans;
    bool success = true;

    if (arr->data != NULL) {
        freeArray(arr);
    }
    initArray(arr);

    fp = fopen(TRANSACTION_FILE, "rb");
    if (fp == NULL) {
        return true;
    }

    while (fread(&recordAccount, sizeof(int), 1, fp) == 1) {
        if (fread(&type_len, sizeof(int), 1, fp) != 1) {
            printf("Warning: transactions log may be corrupted.\n");
            success = false;
            break;
        }

        if (type_len < 0 || type_len > MAX_TYPE_LEN) {
            printf("Warning: transactions log contains invalid data.\n");
            success = false;
            break;
        }

        if (fread(trans.type, sizeof(char), (size_t)type_len, fp) != (size_t)type_len) {
            printf("Warning: transactions log may be corrupted.\n");
            success = false;
            break;
        }
        trans.type[type_len] = '\0';

        if (fread(&trans.amount, sizeof(int), 1, fp) != 1) {
            printf("Warning: transactions log may be corrupted.\n");
            success = false;
            break;
        }

        if (fread(&trans.timestamp, sizeof(time_t), 1, fp) != 1) {
            printf("Warning: transactions log may be corrupted.\n");
            success = false;
            break;
        }

        if (recordAccount == accountNumber) {
            addTransaction(arr, trans);
        }
    }

    fclose(fp);
    return success;
}

bool appendTransactionRecord(int accountNumber, const char *type, int amount, time_t timestamp) {
    FILE *fp;
    int type_len;

    if (type == NULL) {
        return false;
    }

    fp = fopen(TRANSACTION_FILE, "ab");
    if (fp == NULL) {
        printf("Warning: Could not open transactions log for writing.\n");
        return false;
    }

    type_len = (int)strlen(type);
    if (type_len < 0 || type_len > MAX_TYPE_LEN) {
        printf("Warning: Invalid transaction type length.\n");
        fclose(fp);
        return false;
    }

    if (fwrite(&accountNumber, sizeof(int), 1, fp) != 1 ||
        fwrite(&type_len, sizeof(int), 1, fp) != 1 ||
        fwrite(type, sizeof(char), (size_t)type_len, fp) != (size_t)type_len ||
        fwrite(&amount, sizeof(int), 1, fp) != 1 ||
        fwrite(&timestamp, sizeof(time_t), 1, fp) != 1) {
        printf("Warning: Failed to write transaction record.\n");
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

void ensureBankFileExists(void) {
    FILE *fp = fopen(BANK_FILE, "ab");
    if (fp != NULL) {
        fclose(fp);
        return;
    }

    printf("\nError: Unable to access account file.\n");
}

void ensureTransactionFileExists(void) {
    FILE *fp = fopen(TRANSACTION_FILE, "ab");
    if (fp != NULL) {
        fclose(fp);
    }
}

bool loadAccountByCredentials(int accNum, int pin, struct account *result) {
    FILE *fp;
    AccountReadStatus status;
    struct account acc;
    unsigned char enteredHash[HASH_SIZE];
    unsigned char storedHash[HASH_SIZE];

    fp = fopen(BANK_FILE, "rb");
    if (fp == NULL) {
        printf("\nFile cannot be opened...\n");
        return false;
    }

    hash_pin_value(pin, enteredHash);

    while ((status = readAccount(fp, &acc)) == ACCOUNT_READ_OK) {
        if (acc.num == accNum) {
            hash_pin_value(acc.pin, storedHash);
            if (memcmp(enteredHash, storedHash, HASH_SIZE) == 0) {
                *result = acc;
                fclose(fp);
                return true;
            }
        }
    }

    if (status == ACCOUNT_READ_ERROR) {
        printf("\nError: Account file is corrupted.\n");
    }

    fclose(fp);
    return false;
}

bool updateAccountRecord(const struct account *updated) {
    FILE *fp, *temp;
    AccountReadStatus status;
    struct account acc;
    int found = 0;

    fp = fopen(BANK_FILE, "rb");
    if (fp == NULL) {
        printf("\nError: File cannot be opened.\n");
        return false;
    }

    temp = fopen(TEMP_FILE, "wb");
    if (temp == NULL) {
        printf("\nError: Cannot create temporary file.\n");
        fclose(fp);
        return false;
    }

    while ((status = readAccount(fp, &acc)) == ACCOUNT_READ_OK) {
        if (acc.num == updated->num) {
            found = 1;
            if (!writeAccount(temp, updated)) {
                printf("\nError: Failed to write account data.\n");
                fclose(fp);
                fclose(temp);
                remove(TEMP_FILE);
                return false;
            }
        } else {
            if (!writeAccount(temp, &acc)) {
                printf("\nError: Failed to write account data.\n");
                fclose(fp);
                fclose(temp);
                remove(TEMP_FILE);
                return false;
            }
        }
    }

    if (status == ACCOUNT_READ_ERROR) {
        printf("\nError: Account file is corrupted.\n");
        fclose(fp);
        fclose(temp);
        remove(TEMP_FILE);
        return false;
    }

    fclose(fp);
    fclose(temp);

    if (!found) {
        remove(TEMP_FILE);
        return false;
    }

    if (remove(BANK_FILE) != 0) {
        printf("\nError: Unable to update account file.\n");
        remove(TEMP_FILE);
        return false;
    }

    if (rename(TEMP_FILE, BANK_FILE) != 0) {
        printf("\nError: Unable to finalize account update.\n");
        return false;
    }

    return true;
}

int managerLogin(void) {
    FILE *fm;
    char enteredID[MAX_ID_LEN + 1];
    char enteredPassword[MAX_PASS_LEN + 1];
    int stored_id_length;
    char stored_id[MAX_ID_LEN + 1];
    unsigned char salt[SALT_SIZE];
    unsigned char stored_hash[HASH_SIZE];
    unsigned char computed_hash[HASH_SIZE];

    fm = fopen(MANAGER_FILE, "rb");
    if (fm == NULL) {
        printf("\nManager credentials file not found. Please run ManagerSetup.c first.\n");
        return 0;
    }

    if (fread(&stored_id_length, sizeof(int), 1, fm) != 1) {
        printf("\nError: Corrupted manager file.\n");
        fclose(fm);
        return 0;
    }

    if (stored_id_length < 0 || stored_id_length > MAX_ID_LEN) {
        printf("\nError: Corrupted manager file.\n");
        fclose(fm);
        return 0;
    }

    if (fread(stored_id, sizeof(char), (size_t)stored_id_length, fm) != (size_t)stored_id_length) {
        printf("\nError: Corrupted manager file.\n");
        fclose(fm);
        return 0;
    }
    stored_id[stored_id_length] = '\0';

    if (fread(salt, sizeof(unsigned char), SALT_SIZE, fm) != SALT_SIZE) {
        printf("\nError: Corrupted manager file.\n");
        fclose(fm);
        return 0;
    }

    if (fread(stored_hash, sizeof(unsigned char), HASH_SIZE, fm) != HASH_SIZE) {
        printf("\nError: Corrupted manager file.\n");
        fclose(fm);
        return 0;
    }

    fclose(fm);

    printf("\nEnter the Manager ID: ");
    getLine(enteredID, sizeof(enteredID));

    if (strcmp(enteredID, stored_id) != 0) {
        printf("\nManager ID not found. Access denied.\n");
        return 0;
    }

    printf("Enter the password: ");
    getPassword(enteredPassword, sizeof(enteredPassword));

    hash_password(salt, enteredPassword, computed_hash);

    if (memcmp(computed_hash, stored_hash, HASH_SIZE) != 0) {
        printf("\nIncorrect password. Access denied.\n");
        return 0;
    }

    printf("\n.....Access Granted.....\n");
    return 1;
}

void list(void) {
    FILE *fp;
    struct account acc;
    int found = 0;
    AccountReadStatus status;

    fp = fopen(BANK_FILE, "rb");
    if (fp == NULL) {
        printf("\nNo accounts found. File cannot be opened.\n");
        return;
    }

    printf("\nAccount Name       Account Number       Account PIN       Account Balance\n");
    printf("----------------------------------------------------------------------------\n");

    while ((status = readAccount(fp, &acc)) == ACCOUNT_READ_OK) {
        found = 1;
        printf("%-20s %-20d %-20d %-20d\n", acc.name, acc.num, acc.pin, acc.balance);
    }

    if (status == ACCOUNT_READ_ERROR) {
        printf("\nError: Account file is corrupted.\n");
    }

    if (!found) {
        printf("No accounts found.\n");
    }

    fclose(fp);
}

void search(void) {
    FILE *fp;
    struct account acc;
    char searchQuery[MAX_NAME_LEN + 1];
    char *endptr;
    long searchNum;
    int found = 0;
    AccountReadStatus status;

    fp = fopen(BANK_FILE, "rb");
    if (fp == NULL) {
        printf("\nError: File cannot be opened.\n");
        return;
    }

    printf("\nEnter the Account Name or Account Number to search: ");
    getLine(searchQuery, sizeof(searchQuery));

    errno = 0;
    searchNum = strtol(searchQuery, &endptr, 10);
    if (errno != 0 || endptr == searchQuery || *endptr != '\0') {
        searchNum = LONG_MIN;
    }

    printf("\nAccount Name       Account Number       Account PIN       Account Balance\n");
    printf("----------------------------------------------------------------------------\n");

    while ((status = readAccount(fp, &acc)) == ACCOUNT_READ_OK) {
        if (strstr(acc.name, searchQuery) != NULL || (searchNum != LONG_MIN && acc.num == (int)searchNum)) {
            found = 1;
            printf("%-20s %-20d %-20d %-20d\n", acc.name, acc.num, acc.pin, acc.balance);
        }
    }

    if (status == ACCOUNT_READ_ERROR) {
        printf("\nError: Account file is corrupted.\n");
    }

    if (!found) {
        printf("\nNo matching account found.\n");
    } else {
        printf("\nSearch completed.\n");
    }

    fclose(fp);
}

void add(void) {
    FILE *fp;
    struct account acc;
    char choice[8];

    fp = fopen(BANK_FILE, "ab");
    if (fp == NULL) {
        printf("\nError: File cannot be created/opened.\n");
        return;
    }

    strcpy(choice, "y");
    while (choice[0] == 'y' || choice[0] == 'Y') {
        printf("\nEnter Holder name: ");
        getLine(acc.name, sizeof(acc.name));

        if (strlen(acc.name) == 0) {
            printf("\nError: Account name cannot be empty.\n");
            continue;
        }

        printf("Enter Account number: ");
        acc.num = getInt();

        printf("Enter Account pin: ");
        acc.pin = getInt();

        printf("Enter Account opening balance: ");
        acc.balance = getInt();

        if (!writeAccount(fp, &acc)) {
            printf("\nError: Failed to save account.\n");
            fclose(fp);
            return;
        }

        printf("\nAccount added successfully.\n");
        printf("Want to add more records? (y/n): ");
        getLine(choice, sizeof(choice));
        if (choice[0] == '\0') {
            strcpy(choice, "n");
        }
    }

    fclose(fp);
}

void modify(void) {
    FILE *fp, *temp;
    struct account acc;
    int mnum, found = 0;
    AccountReadStatus status;

    fp = fopen(BANK_FILE, "rb");
    if (fp == NULL) {
        printf("\nError: File cannot be opened.\n");
        return;
    }

    temp = fopen(TEMP_FILE, "wb");
    if (temp == NULL) {
        printf("\nError: Cannot create temporary file.\n");
        fclose(fp);
        return;
    }

    printf("\nEnter A/c num of the holder whose record needs to be changed: ");
    mnum = getInt();

    while ((status = readAccount(fp, &acc)) == ACCOUNT_READ_OK) {
        if (mnum == acc.num) {
            found = 1;
            printf("\nAccount name       Account number       Account pin        Account balance\n");
            printf("%-20s %-20d %-20d %-20d\n", acc.name, acc.num, acc.pin, acc.balance);

            printf("\nEnter Holder name: ");
            getLine(acc.name, sizeof(acc.name));

            printf("Enter Account number: ");
            acc.num = getInt();

            printf("Enter Account pin: ");
            acc.pin = getInt();

            printf("Enter Account balance: ");
            acc.balance = getInt();
        }

        if (!writeAccount(temp, &acc)) {
            printf("\nError: Failed to write account data.\n");
            fclose(fp);
            fclose(temp);
            remove(TEMP_FILE);
            return;
        }
    }

    if (status == ACCOUNT_READ_ERROR) {
        printf("\nError: Account file is corrupted.\n");
        fclose(fp);
        fclose(temp);
        remove(TEMP_FILE);
        return;
    }

    fclose(fp);
    fclose(temp);

    if (!found) {
        printf("\nNo record found with account number: %d\n", mnum);
        remove(TEMP_FILE);
    } else {
        remove(BANK_FILE);
        rename(TEMP_FILE, BANK_FILE);
        printf("\nAccount modified successfully.\n");
    }
}

void deleteAccount(void) {
    FILE *fp, *temp;
    struct account acc;
    char searchQuery[MAX_NAME_LEN + 1];
    char *endptr;
    long searchNum;
    int found = 0;
    AccountReadStatus status;

    fp = fopen(BANK_FILE, "rb");
    if (fp == NULL) {
        printf("\nError: File cannot be opened.\n");
        return;
    }

    temp = fopen(TEMP_FILE, "wb");
    if (temp == NULL) {
        printf("\nError: Cannot create temporary file.\n");
        fclose(fp);
        return;
    }

    printf("\nEnter the Account Name or Account Number to delete: ");
    getLine(searchQuery, sizeof(searchQuery));

    errno = 0;
    searchNum = strtol(searchQuery, &endptr, 10);
    if (errno != 0 || endptr == searchQuery || *endptr != '\0') {
        searchNum = LONG_MIN;
    }

    while ((status = readAccount(fp, &acc)) == ACCOUNT_READ_OK) {
        if ((searchNum != LONG_MIN && acc.num == (int)searchNum) || strcmp(acc.name, searchQuery) == 0) {
            found = 1;
            printf("\nAccount with Name: %s and Number: %d will be deleted.\n", acc.name, acc.num);
        } else {
            if (!writeAccount(temp, &acc)) {
                printf("\nError: Failed to write account data.\n");
                fclose(fp);
                fclose(temp);
                remove(TEMP_FILE);
                return;
            }
        }
    }

    if (status == ACCOUNT_READ_ERROR) {
        printf("\nError: Account file is corrupted.\n");
        fclose(fp);
        fclose(temp);
        remove(TEMP_FILE);
        return;
    }

    fclose(fp);
    fclose(temp);

    if (!found) {
        printf("\nNo matching account found.\n");
        remove(TEMP_FILE);
    } else {
        remove(BANK_FILE);
        rename(TEMP_FILE, BANK_FILE);
        printf("\nAccount deleted successfully.\n");
    }
}

void manager(void) {
    int ch;

    if (!managerLogin()) {
        return;
    }

    printf("\n1. List all accounts\n2. Search a record\n3. Add account\n4. Modify existing account\n5. Delete account\n6. Exit");

    while (1) {
        printf("\n\nEnter your choice of operation: ");
        ch = getInt();

        switch (ch) {
            case 1: list(); break;
            case 2: search(); break;
            case 3: add(); break;
            case 4: modify(); break;
            case 5: deleteAccount(); break;
            case 6:
                printf("\n*****Thank You For Using Our System*****\n");
                exit(0);
            default:
                printf("\nEnter the correct choice!!!\n");
        }
    }
}

int deposit(struct account *acc) {
    int amount;
    struct transaction trans;

    printf("\nYour current balance = %d", acc->balance);
    printf("\nEnter the amount you want to deposit: ");
    amount = getInt();

    if (amount <= 0) {
        printf("\nInvalid amount. Deposit cancelled.\n");
        return acc->balance;
    }

    if (amount > INT_MAX - acc->balance) {
        printf("\nDeposit would overflow the balance.\n");
        return acc->balance;
    }

    acc->balance += amount;

    strcpy(trans.type, "Deposit");
    trans.amount = amount;
    trans.timestamp = time(NULL);
    addTransaction(&acc->trans, trans);
    if (!appendTransactionRecord(acc->num, trans.type, trans.amount, trans.timestamp)) {
        printf("Warning: Failed to record deposit transaction.\n");
    }

    return acc->balance;
}

int withdraw(struct account *acc) {
    int amount;
    struct transaction trans;

    printf("\nYour current balance = %d", acc->balance);
    printf("\nEnter the amount you want to take out: ");
    amount = getInt();

    if (amount <= 0) {
        printf("\nInvalid amount. Withdrawal cancelled.\n");
        return acc->balance;
    }

    if (amount <= acc->balance) {
        acc->balance -= amount;
        printf("\nWithdrawal successful!!!\n");

        strcpy(trans.type, "Withdrawal");
        trans.amount = amount;
        trans.timestamp = time(NULL);
        addTransaction(&acc->trans, trans);
        if (!appendTransactionRecord(acc->num, trans.type, trans.amount, trans.timestamp)) {
            printf("Warning: Failed to record withdrawal transaction.\n");
        }

        return acc->balance;
    } else {
        printf("\nInsufficient balance!!!\n");
        return acc->balance;
    }
}

void details(struct account *acc, int pointer) {
    if (pointer == 1) {
        printf("\n\n....Account Details....\n");
        printf("Name of the account holder = %s\n", acc->name);
        printf("Account number = %d\n", acc->num);
        printf("Balance = %d\n", acc->balance);
    } else if (pointer == 2) {
        printf("\n\n....The receipt....\n");
        printf("Name of the account holder = %s\n", acc->name);
        printf("Account number = %d\n", acc->num);
        if (acc->trans.size > 0) {
            printf("The amount added = %d\n", acc->trans.data[acc->trans.size - 1].amount);
        }
        printf("Balance = %d\n", acc->balance);
    } else if (pointer == 3) {
        printf("\n\n....The receipt....\n");
        printf("Name of the account holder = %s\n", acc->name);
        printf("Account number = %d\n", acc->num);
        if (acc->trans.size > 0) {
            printf("The amount taken out = %d\n", acc->trans.data[acc->trans.size - 1].amount);
        }
        printf("Balance = %d\n", acc->balance);
    }
}

void customer(void) {
    struct account acc;
    int n, enteredPin, ch;

    ensureBankFileExists();

    printf("\nEnter the Account number: ");
    n = getInt();

    if (!promptMaskedPin(&enteredPin)) {
        printf("Unable to read PIN.\n");
        return;
    }

    if (!loadAccountByCredentials(n, enteredPin, &acc)) {
        printf("......User Credential not matched........\n");
        return;
    }

    if (!loadTransactionsForAccount(acc.num, &acc.trans)) {
        printf("\nWarning: Unable to load transaction history.\n");
    }

    printf("A/c Details Matched\n");
    printf("\n\n1. Check info\n2. Deposit\n3. Withdraw\n4. Exit\n");

    while (1) {
        printf("\n---------------------------------------------------------------------------------------------------------------------------------\n");
        printf("\nEnter your choice of operation: ");
        ch = getInt();

        switch (ch) {
            case 1:
                details(&acc, 1);
                break;

            case 2:
                acc.balance = deposit(&acc);
                details(&acc, 2);
                break;

            case 3:
                acc.balance = withdraw(&acc);
                details(&acc, 3);
                break;

            case 4:
                if (!updateAccountRecord(&acc)) {
                    printf("\nError: Failed to update account balance.\n");
                }
                freeArray(&acc.trans);
                printf("\n*****Thank You For Using Our System*****\n");
                return;

            default:
                printf("\nEnter correct choice!!!\n");
        }
    }
}

int main(void) {
    int choice;

    ensureBankFileExists();
    ensureTransactionFileExists();

    printf("                                                  Welcome to Bank Management System \n");
    printf("                                                                            created by:- Chiranjivi R\n");
    printf("\n--------------------------------------------------------------------------------------------------------------------------------");
    printf("\nLOGIN AS \n1. MANAGER \n2. CUSTOMER \n3. EXIT");
    printf("\nEnter your choice: ");
    choice = getInt();

    switch (choice) {
        case 1:
            manager();
            break;

        case 2:
            customer();
            break;

        case 3:
            printf("\n*****Thank You For Using Our System*****");
            printf("\n----------------------------------------------------------------------------------------------------------------------------------\n");
            exit(0);

        default:
            printf("\nEnter the correct choice!!!\n");
    }

    return 0;
}
