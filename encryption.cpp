#include <cstdio>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <windows.h>
#include <ntsecapi.h>

// Supported hashing algorithms
#define SHA256 1
#define SHA512 2

// Supported encryption algorithms
#define DES3 1
#define AES128 2
#define AES256 3

char* progname;

// function for generating master key, encryption key, and hmac key
void generateKeys(char* password, unsigned char* mastersalt,
    const EVP_MD* hashalg, size_t keysize, size_t blocksize, int iterations,
    unsigned char*& masterkey, unsigned char*& encryptionkey,
    unsigned char*& hmackey) {

    // start timer for measuring master key derivation time
    SYSTEMTIME st, ed;
    GetSystemTime(&st);

    // generate master key
    PKCS5_PBKDF2_HMAC(password, strlen(password), mastersalt,
        blocksize, iterations, hashalg, keysize, masterkey);

    // report master key derivation time measurement
    GetSystemTime(&ed);
    printf("Master key derivation time: %02d.%02d second(s)\n",
        (ed.wSecond - st.wSecond), (ed.wMilliseconds - st.wMilliseconds));

    // generate encryption key with "encryption" as salt
    unsigned char* encryptionsalt = (unsigned char*)"encryption";
    PKCS5_PBKDF2_HMAC((char*)masterkey, keysize, encryptionsalt,
        strlen((char*)encryptionsalt), 1, hashalg, keysize, encryptionkey);

    // generate hmac key with "hmac" as salt
    unsigned char* hmacsalt = (unsigned char*)"hmac";
    PKCS5_PBKDF2_HMAC((char*)masterkey, keysize, hmacsalt,
        strlen((char*)hmacsalt), 1, hashalg, keysize, hmackey);
}

// function for hmac of IV and ciphertext
unsigned int hmac(unsigned char* md_value, unsigned char* ciphertext,
    int ciphertext_len, unsigned char* iv, size_t blocksize,
    unsigned char* key, size_t keysize, const EVP_MD* hashalg) {

    unsigned int len;
    HMAC_CTX* ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, key, keysize, hashalg, NULL);
    HMAC_Update(ctx, iv, blocksize);
    HMAC_Update(ctx, ciphertext, ciphertext_len);
    HMAC_Final(ctx, md_value, &len);
    HMAC_CTX_free(ctx);

    return len;
}

// function for encrypting file
int encrypt(unsigned char* plaintext, unsigned char* ciphertext,
    const EVP_CIPHER* cipher, unsigned char* key, unsigned char* iv) {

    int len;
    int plaintext_len = strlen((char*)plaintext);
    int ciphertext_len;
    int rc;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    rc = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    if (rc != 1) {
        printf("EVP_EncryptInit_ex() error\n");
        return -1;
    }

    rc = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (rc != 1) {
        printf("EVP_EncryptUpdate() error\n");
        return -1;
    }

    ciphertext_len = len;

    rc = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    if (rc != 1) {
        printf("EVP_EncryptFinal_ex() error\n");
        return -1;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// function is called when user wants to encrypt a file
int doEncryption(char* input, char* output, char* password, int iterations,
    size_t keysize, const EVP_MD* hashalg, size_t blocksize,
    const EVP_CIPHER* cipher) {

    // open and read in input file
    int rc;
    FILE* inputFile;
    int bufflen;
    char* buffer;

    inputFile = fopen(input, "rb");
    if (inputFile == NULL) {
        printf("Error opening %s\n", input);
        return -1;
    }

    fseek(inputFile, 0, SEEK_END);
    bufflen = ftell(inputFile);
    rewind(inputFile);

    buffer = (char*)malloc(sizeof(char) * bufflen);
    if (buffer == NULL) {
        printf("Memory allocation error\n");
        return -1;
    }

    rc = fread(buffer, 1, bufflen, inputFile);
    if (rc != bufflen) {
        printf("Error reading %s\n", input);
        return -1;
    }

    fclose(inputFile);

    // generate random master salt for master key
    unsigned char* mastersalt = (unsigned char*)malloc(blocksize);
    RtlGenRandom(mastersalt, blocksize);

    // generate master key, encryption key, and hmac key
    unsigned char* masterkey =
        (unsigned char*)malloc(sizeof(char) * keysize);
    unsigned char* encryptionkey =
        (unsigned char*)malloc(sizeof(char) * keysize);
    unsigned char* hmackey =
        (unsigned char*)malloc(sizeof(char) * keysize);
    generateKeys(password, mastersalt, hashalg, keysize, blocksize, iterations,
        masterkey, encryptionkey, hmackey);

    // encrypt file
    printf("Encrypting file...\n");

    unsigned char* iv = (unsigned char*)malloc(blocksize);
    RtlGenRandom(iv, blocksize);

    unsigned char* ciphertext = (unsigned char*)malloc(bufflen + blocksize);
    int ciphertext_len = encrypt((unsigned char*)buffer, ciphertext, cipher,
        encryptionkey, iv);

    // hmac IV and ciphertext
    printf("Creating HMAC...\n");
    unsigned char* md_value = (unsigned char*)malloc(keysize);
    rc = hmac(md_value, ciphertext, ciphertext_len, iv, blocksize, hmackey,
        keysize, hashalg);
    if (rc != (int)keysize) {
        printf("HMAC error\n");
        return -1;
    }

    // write output file
    FILE* outputFile;

    outputFile = fopen(output, "wb");
    if (outputFile == NULL) {
        printf("Error opening %s\n", output);
        return -1;
    }

    // write master key derivation iterations to output file
    rc = fwrite(&iterations, 1, sizeof(iterations), outputFile);
    if (rc != sizeof(iterations)) {
        printf("Error writing %s\n", output);
        return -1;
    }

    // write hashing algorithm to output file
    unsigned short hashOp;
    if (hashalg == EVP_sha256()) {
        hashOp = SHA256;
    } else if (hashalg == EVP_sha512()) {
        hashOp = SHA512;
    }
    rc = fwrite(&hashOp, 1, sizeof(hashOp), outputFile);
    if (rc != sizeof(hashOp)) {
        printf("Error writing %s\n", output);
        return -1;
    }

    // write encryption algorithm to output file
    unsigned short encryptOp;
    if (cipher == EVP_des_ede3_cbc()) {
        encryptOp = DES3;
    } else if (cipher == EVP_aes_128_cbc()) {
        encryptOp = AES128;
    } else if (cipher == EVP_aes_256_cbc()) {
        encryptOp = AES256;
    }
    rc = fwrite(&encryptOp, 1, sizeof(encryptOp), outputFile);
    if (rc != sizeof(encryptOp)) {
        printf("Error writing %s\n", output);
        return -1;
    }

    // write master salt to output file
    rc = fwrite(mastersalt, 1, blocksize, outputFile);
    if (rc != (int)blocksize) {
        printf("Error writing %s\n", output);
        return -1;
    }

    // write HMAC to output file
    rc = fwrite(md_value, 1, keysize, outputFile);
    if (rc != (int)keysize) {
        printf("Error writing %s\n", output);
        return -1;
    }

    // write IV to output file
    rc = fwrite(iv, 1, blocksize, outputFile);
    if (rc != (int)blocksize) {
        printf("Error writing %s\n", output);
        return -1;
    }

    // write ciphertext_len to output file
    rc = fwrite(&ciphertext_len, 1, sizeof(ciphertext_len), outputFile);
    if (rc != sizeof(ciphertext_len)) {
        printf("Error writing %s\n", output);
        return -1;
    }

    // write ciphertext to output file
    rc = fwrite(ciphertext, 1, ciphertext_len, outputFile);
    if (rc != ciphertext_len) {
        printf("Error writing %s\n", output);
        return -1;
    }

    printf("Encrypted file is complete!\n");
    fclose(outputFile);
    free(buffer);
    free(mastersalt);
    free(masterkey);
    free(encryptionkey);
    free(hmackey);
    free(iv);
    free(ciphertext);
    free(md_value);

    return 0;
}

// function for decrypting file
int decrypt(unsigned char* ciphertext, unsigned char* plaintext,
    const EVP_CIPHER* cipher, unsigned char* key, unsigned char* iv) {
    int len;
    int plaintext_len;
    int ciphertext_len = strlen((char*)ciphertext);
    int rc;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    rc = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    if (rc != 1) {
        printf("EVP_DecryptInit_ex() error\n");
        return -1;
    }

    rc = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    if (rc != 1) {
        printf("EVP_DecryptUpdate() error\n");
        return -1;
    }

    plaintext_len = len;

    rc = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (rc != 1) {
        printf("EVP_DecryptFinal_ex() error\n");
        return -1;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// function is called when user wants to decrypt a file
int doDecryption(char* input, char* output, char* password) {

    // open input file
    int rc;
    FILE* inputFile;

    inputFile = fopen(input, "rb");
    if (inputFile == NULL) {
        printf("Error opening %s\n", input);
        return -1;
    }

    // determine iterations for master key derivation from encrypted file
    int iterations;
    rc = fread(&iterations, 1, sizeof(iterations), inputFile);
    if (rc != sizeof(iterations)) {
        printf("Error reading %s\n", input);
        return -1;
    }


    // determine hashing algorithm from encrypted file
    size_t keysize;
    const EVP_MD* hashalg;
    unsigned short hashOp;
    rc = fread(&hashOp, 1, sizeof(hashOp), inputFile);
    if (rc != sizeof(hashOp)) {
        printf("Error reading %s\n", input);
        return -1;
    }

    if (hashOp == SHA256) {
        keysize = 32;
        hashalg = EVP_sha256();
    } else if (hashOp == SHA512) {
        keysize = 64;
        hashalg = EVP_sha512();
    }

    // determine encryption algorithm from encrypted file
    size_t blocksize;
    const EVP_CIPHER* cipher;
    unsigned short encryptOp;
    rc = fread(&encryptOp, 1, sizeof(encryptOp), inputFile);
    if (rc != sizeof(encryptOp)) {
        printf("Error reading %s\n", input);
        return -1;
    }

    if (encryptOp == DES3) {
        blocksize = 8;
        cipher = EVP_des_ede3_cbc();
    } else if (encryptOp == AES128) {
        blocksize = 16;
        cipher = EVP_aes_128_cbc();
    } else if (encryptOp == AES256) {
        blocksize = 16;
        cipher = EVP_aes_256_cbc();
    }

    // determine salt from encrypted file
    unsigned char* mastersalt = (unsigned char*)malloc(blocksize);
    rc = fread(mastersalt, 1, blocksize, inputFile);
    if (rc != (int)blocksize) {
        printf("Error reading %s\n", input);
        return -1;
    }

    // generate master key, encryption key, and hmac key
    unsigned char* masterkey =
        (unsigned char*)malloc(sizeof(char) * keysize);
    unsigned char* encryptionkey =
        (unsigned char*)malloc(sizeof(char) * keysize);
    unsigned char* hmackey =
        (unsigned char*)malloc(sizeof(char) * keysize);
    generateKeys(password, mastersalt, hashalg, keysize, blocksize, iterations,
        masterkey, encryptionkey, hmackey);

    // determine hash from encrypted file
    unsigned char* md_value = (unsigned char*)malloc(keysize);
    rc = fread(md_value, 1, keysize, inputFile);
    if (rc != (int)keysize) {
        printf("Error reading %s\n", input);
        return -1;
    }

    // determine IV from encrypted file
    unsigned char* iv = (unsigned char*)malloc(blocksize);
    rc = fread(iv, 1, blocksize, inputFile);
    if (rc != (int)blocksize) {
        printf("Error reading %s\n", input);
        return -1;
    }

    // determine ciphertext_len from encrypted file
    int ciphertext_len;
    rc = fread(&ciphertext_len, 1, sizeof(ciphertext_len), inputFile);
    if (rc != sizeof(ciphertext_len)) {
        printf("Error reading %s\n", input);
        return -1;
    }

    // determine ciphertext from encrypted file
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    rc = fread(ciphertext, 1, ciphertext_len, inputFile);
    if (rc != ciphertext_len) {
        printf("Error reading %s\n", input);
        return -1;
    }

    fclose(inputFile);

    // calculate hash of IV and ciphertext for comparison
    unsigned char* md_verify = (unsigned char*)malloc(keysize);
    rc = hmac(md_verify, ciphertext, ciphertext_len, iv, blocksize, hmackey,
        keysize, hashalg);
    if (rc != (int)keysize) {
        printf("HMAC error\n");
        return -1;
    }

    // verify that the hash from the encrypted file matches calculated hash
    if (memcmp(md_value, md_verify, keysize) != 0) {
        printf("HMAC does not match\n");
        return -1;
    }
    printf("HMAC matches\n");

    //decrypt file
    printf("Decrypting file...\n");

    char* plaintext = (char*)malloc(sizeof(char) * ciphertext_len);

    int plaintext_len = decrypt(ciphertext, (unsigned char*)plaintext, cipher,
        encryptionkey, iv);

    // write decrypted text to file
    FILE* decryptFile;

    decryptFile = fopen(output, "wb");
    if (decryptFile == NULL) {
        printf("Error opening %s\n", output);
        return -1;
    }

    rc = fwrite(plaintext, 1, plaintext_len, decryptFile);
    if (rc != plaintext_len) {
        printf("Error writing %s\n", output);
        return -1;
    }

    printf("Decrypted file complete!\n");
    fclose(decryptFile);
    free(mastersalt);
    free(masterkey);
    free(encryptionkey);
    free(hmackey);
    free(md_value);
    free(iv);
    free(ciphertext);
    free(md_verify);
    free(plaintext);

    return 0;
}

int main(int argc, char* argv[]) {
    progname = argv[0];
    int rc;

    if (strcmp(argv[1], "-e") == 0) {
        // Encrypting a file
        
        // Arguments: 1. encrypt/decrypt; 2.input file; 3.output file;
        // 4.password; 5.master key derivation iterations
        // 6.hash algorithm (SHA256 or SHA512);
        // 7. encryption algorithm (3DES, AES128, or AES256)
        if (argc != 8) {
            printf("%s: Invalid number of arguments\n", progname);
            printf("Usage: %s -e input_file output_file password ", progname);
            printf("derivation_iterations hash_algorithm ");
            printf("encryption_algorithm\n");
            return -1;
        }
        
        char* input = argv[2];
        char* output = argv[3];
        char* password = argv[4];
        int iterations = std::stoi(argv[5]);

        size_t keysize;
        const EVP_MD* hashalg;
        if (strcmp(argv[6], "sha256") == 0) {
            keysize = 32;
            hashalg = EVP_sha256();
        }
        else if (strcmp(argv[6], "sha512") == 0) {
            keysize = 64;
            hashalg = EVP_sha512();
        }
        else {
            printf("Hash algorithm is not supported\n");
            return -1;
        }

        size_t blocksize;
        const EVP_CIPHER* cipher;
        if (strcmp(argv[7], "3des") == 0) {
            blocksize = 8;
            cipher = EVP_des_ede3_cbc();
        }
        else if (strcmp(argv[7], "aes128") == 0) {
            blocksize = 16;
            cipher = EVP_aes_128_cbc();
        }
        else if (strcmp(argv[7], "aes256") == 0) {
            blocksize = 16;
            cipher = EVP_aes_256_cbc();
        }
        else {
            printf("Encryption algorithm is not supported\n");
            return -1;
        }

        // program will encrypt input file
        rc = doEncryption(input, output, password, iterations, keysize,
            hashalg, blocksize, cipher);
        if (rc != 0) {
            printf("Encryption failed\n");
            return -1;
        }

        free(input);
        free(output);
        free(password);

    } else if (strcmp(argv[1], "-d") == 0) {
        // Decrypting a file
        
        // Arguments: 1. encrypt/decrypt; 2.input file; 3.output file;
        // 4.password
        // Decrypt metadata: iterations, hash algo, encryption algo
        if (argc != 5) {
            printf("%s: Invalid number of arguments\n", progname);
            printf("Usage: %s encrypt/decrypt input_file ", progname);
            printf("output_file password");
            return -1;
        }
        
        char* input = argv[2];
        char* output = argv[3];
        char* password = argv[4];
        
        // program will decrypt input file
        rc = doDecryption(input, output, password);
        if (rc != 0) {
            printf("Decryption failed\n");
            return -1;
        }

        free(input);
        free(output);
        free(password);

    } else {
        printf("Task is neither encrypt or decrypt\n");
        return -1;
    }

	return 0;
}