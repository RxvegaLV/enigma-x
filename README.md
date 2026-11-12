# enigma-x
program that encrypts any files with a seed set by the user.

ENIGMA-X is a C++ file encryption utility for Windows, built around Microsoft's BCrypt Cryptography API (CNG).

It uses AES-256-GCM for authenticated encryption and PBKDF2-HMAC-SHA256 for deriving encryption keys from user-provided seeds.

IMPORTANT!

The encryption seed is never intentionally stored in the encrypted file.

A random salt is generated for every encryption operation.

Encryption uses randomly generated nonces.

Authentication tags are checked during decryption.

The application does not rely on file extensions to identify encrypted files.ab


*HOW TO USE*
Run the application

Choose and option

enter file name (or directory if it's not next to the program)

enter result file name

done!

#######################################################

Have fun evading forensics!
