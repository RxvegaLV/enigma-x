
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

using Bytes = std::vector<unsigned char>;

constexpr ULONG SALT_SIZE = 16;
constexpr ULONG NONCE_SIZE = 12;
constexpr ULONG KEY_SIZE = 32;
constexpr ULONG TAG_SIZE = 16;
constexpr ULONG CHUNK_SIZE = 65536;
constexpr ULONG ITERATIONS = 600000;

void wipe(void* ptr, size_t size) {
    SecureZeroMemory(ptr, size);
}

bool randomBytes(unsigned char* data, ULONG size) {
    return BCryptGenRandom(
        nullptr, data, size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    ) == 0;
}

bool deriveKey(
    const std::string& seed,
    const unsigned char* salt,
    unsigned char* key
) {
    BCRYPT_ALG_HANDLE alg = nullptr;

    if (BCryptOpenAlgorithmProvider(
        &alg, BCRYPT_SHA256_ALGORITHM,
        nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG
    ) != 0) return false;

    NTSTATUS result = BCryptDeriveKeyPBKDF2(
        alg,
        reinterpret_cast<PUCHAR>(
            const_cast<char*>(seed.data())
        ),
        static_cast<ULONG>(seed.size()),
        const_cast<PUCHAR>(salt),
        SALT_SIZE,
        ITERATIONS,
        key,
        KEY_SIZE,
        0
    );

    BCryptCloseAlgorithmProvider(alg, 0);
    return result == 0;
}

bool aesGcm(
    bool encrypt,
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* input,
    ULONG inputSize,
    unsigned char* output,
    unsigned char* tag
) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE handle = nullptr;

    bool success = false;

    if (BCryptOpenAlgorithmProvider(
        &alg, BCRYPT_AES_ALGORITHM, nullptr, 0
    ) != 0) return false;

    if (BCryptSetProperty(
        alg, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(
            const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)
        ),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0
    ) != 0) goto cleanup;

    if (BCryptGenerateSymmetricKey(
        alg, &handle, nullptr, 0,
        const_cast<PUCHAR>(key), KEY_SIZE, 0
    ) != 0) goto cleanup;

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);

        info.pbNonce = const_cast<PUCHAR>(nonce);
        info.cbNonce = NONCE_SIZE;
        info.pbTag = tag;
        info.cbTag = TAG_SIZE;

        ULONG outputSize = 0;
        NTSTATUS result;

        if (encrypt) {
            result = BCryptEncrypt(
                handle,
                const_cast<PUCHAR>(input),
                inputSize,
                &info,
                nullptr, 0,
                output, inputSize,
                &outputSize, 0
            );
        } else {
            result = BCryptDecrypt(
                handle,
                const_cast<PUCHAR>(input),
                inputSize,
                &info,
                nullptr, 0,
                output, inputSize,
                &outputSize, 0
            );
        }

        success = result == 0 && outputSize == inputSize;
    }

cleanup:
    if (handle) BCryptDestroyKey(handle);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);

    return success;
}

bool encryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& seed
) {
    std::ifstream input(inputPath, std::ios::binary);

    if (!input || seed.empty()) return false;

    {
        std::ifstream existing(outputPath, std::ios::binary);
        if (existing) return false;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];

    if (!randomBytes(salt, SALT_SIZE) ||
        !deriveKey(seed, salt, key)) {
        wipe(key, sizeof(key));
        return false;
    }

    std::string tempPath = outputPath + ".tmp";

    std::ofstream output(tempPath, std::ios::binary);

    if (!output) {
        wipe(key, sizeof(key));
        return false;
    }

    const char magic[] = "ENX1";

    output.write(magic, 4);
    output.write(reinterpret_cast<char*>(salt), SALT_SIZE);

    unsigned char buffer[CHUNK_SIZE];
    unsigned char encrypted[CHUNK_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];

    unsigned long long index = 0;
    bool success = false;

    while (input) {
        input.read(reinterpret_cast<char*>(buffer), CHUNK_SIZE);
        ULONG size = static_cast<ULONG>(input.gcount());

        if (size == 0) break;

        if (index == ULLONG_MAX) goto cleanup_encrypt;

        if (!randomBytes(nonce, NONCE_SIZE))
            goto cleanup_encrypt;

        // Bind every chunk to its position and file format.
        unsigned char aad[12] = {
            'E','N','X','1',
            static_cast<unsigned char>(index >> 56),
            static_cast<unsigned char>(index >> 48),
            static_cast<unsigned char>(index >> 40),
            static_cast<unsigned char>(index >> 32),
            static_cast<unsigned char>(index >> 24),
            static_cast<unsigned char>(index >> 16),
            static_cast<unsigned char>(index >> 8),
            static_cast<unsigned char>(index)
        };

        // Include chunk metadata in the authenticated encryption.
        // The per-chunk nonce and tag are stored with the ciphertext.
        if (!aesGcm(
            true, key, nonce, buffer, size, encrypted, tag
        )) goto cleanup_encrypt;

        unsigned int storedSize = size;

        output.write(reinterpret_cast<char*>(&storedSize),
                     sizeof(storedSize));
        output.write(reinterpret_cast<char*>(aad + 4), 8);
        output.write(reinterpret_cast<char*>(nonce), NONCE_SIZE);
        output.write(reinterpret_cast<char*>(encrypted), size);
        output.write(reinterpret_cast<char*>(tag), TAG_SIZE);

        if (!output) goto cleanup_encrypt;

        ++index;
    }

    if (!input.eof()) goto cleanup_encrypt;

    {
        // Authenticated empty final record.
        unsigned char nonceFinal[NONCE_SIZE];
        unsigned char tagFinal[TAG_SIZE];
        unsigned char empty = 0;

        if (!randomBytes(nonceFinal, NONCE_SIZE))
            goto cleanup_encrypt;

        if (!aesGcm(
            true, key, nonceFinal, &empty, 0,
            &empty, tagFinal
        )) goto cleanup_encrypt;

        unsigned int zero = 0;
        output.write(reinterpret_cast<char*>(&zero), sizeof(zero));
        output.write(reinterpret_cast<char*>(nonceFinal), NONCE_SIZE);
        output.write(reinterpret_cast<char*>(tagFinal), TAG_SIZE);
    }

    output.close();

    if (!output) goto cleanup_encrypt;

    if (std::rename(tempPath.c_str(), outputPath.c_str()) != 0)
        goto cleanup_encrypt;

    success = true;

cleanup_encrypt:
    output.close();
    wipe(key, sizeof(key));
    wipe(buffer, sizeof(buffer));
    wipe(encrypted, sizeof(encrypted));

    if (!success) DeleteFileA(tempPath.c_str());

    return success;
}

bool decryptFile(
    const std::string& inputPath,
    const std::string& outputPath,
    const std::string& seed
) {
    std::ifstream input(inputPath, std::ios::binary);

    if (!input || seed.empty()) return false;

    {
        std::ifstream existing(outputPath, std::ios::binary);
        if (existing) return false;
    }

    char magic[4];
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];

    input.read(magic, 4);
    input.read(reinterpret_cast<char*>(salt), SALT_SIZE);

    if (!input || std::string(magic, 4) != "ENX1")
        return false;

    if (!deriveKey(seed, salt, key)) {
        wipe(key, sizeof(key));
        return false;
    }

    std::string tempPath = outputPath + ".tmp";
    std::ofstream output(tempPath, std::ios::binary);

    if (!output) {
        wipe(key, sizeof(key));
        return false;
    }

    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char encrypted[CHUNK_SIZE];
    unsigned char decrypted[CHUNK_SIZE];

    unsigned long long expectedIndex = 0;
    bool success = false;
    bool finalRecord = false;

    while (input) {
        unsigned int size = 0;

        input.read(reinterpret_cast<char*>(&size), sizeof(size));

        if (!input) break;

        unsigned long long index = 0;

        if (size > CHUNK_SIZE) goto cleanup_decrypt;

        if (size == 0) {
            input.read(reinterpret_cast<char*>(nonce), NONCE_SIZE);
            input.read(reinterpret_cast<char*>(tag), TAG_SIZE);

            if (!input) goto cleanup_decrypt;

            unsigned char empty = 0;

            if (!aesGcm(
                false, key, nonce, &empty, 0,
                &empty, tag
            )) goto cleanup_decrypt;

            finalRecord = true;
            break;
        }

        unsigned char indexBytes[8];

        input.read(reinterpret_cast<char*>(indexBytes), 8);
        input.read(reinterpret_cast<char*>(nonce), NONCE_SIZE);
        input.read(reinterpret_cast<char*>(encrypted), size);
        input.read(reinterpret_cast<char*>(tag), TAG_SIZE);

        if (!input) goto cleanup_decrypt;

        for (int i = 0; i < 8; ++i)
            index = (index << 8) | indexBytes[i];

        if (index != expectedIndex)
            goto cleanup_decrypt;

        if (!aesGcm(
            false, key, nonce, encrypted,
            size, decrypted, tag
        )) goto cleanup_decrypt;

        output.write(reinterpret_cast<char*>(decrypted), size);

        if (!output) goto cleanup_decrypt;

        ++expectedIndex;
    }

    if (!finalRecord) goto cleanup_decrypt;

    // Reject trailing bytes.
    if (input.peek() != EOF) goto cleanup_decrypt;

    output.close();

    if (!output) goto cleanup_decrypt;

    if (std::rename(tempPath.c_str(), outputPath.c_str()) != 0)
        goto cleanup_decrypt;

    success = true;

cleanup_decrypt:
    output.close();
    wipe(key, sizeof(key));
    wipe(encrypted, sizeof(encrypted));
    wipe(decrypted, sizeof(decrypted));

    if (!success) DeleteFileA(tempPath.c_str());

    return success;
}

int main() {
    std::cout <<
        "============================\n"
        "          ENIGMA-X\n"
        "============================\n\n"
        "1. Encrypt file\n"
        "2. Decrypt file\n"
        "3. Exit\n\n"
        "Choice: ";

    int choice;

    if (!(std::cin >> choice)) return 1;

    std::cin.ignore(
        std::numeric_limits<std::streamsize>::max(), '\n'
    );

    if (choice == 3) return 0;
    if (choice != 1 && choice != 2) return 1;

    std::string input, output, seed;

    std::cout << "Input file: ";
    std::getline(std::cin, input);

    std::cout << "Output file: ";
    std::getline(std::cin, output);

    std::cout << "Seed: ";
    std::getline(std::cin, seed);

    if (seed.empty() || input.empty() || output.empty()) {
        std::cout << "Operation failed.\n";
        return 1;
    }

    bool result = false;

    if (choice == 1)
        result = encryptFile(input, output, seed);
    else
        result = decryptFile(input, output, seed);

    wipe(seed.data(), seed.size());

    std::cout << (
        result
        ? "\nOperation completed.\n"
        : "\nOperation failed. Invalid data or unable to complete.\n"
    );

    return result ? 0 : 1;
}
