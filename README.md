# Advanced Encryption Standard (AES) Project

This repository hosts an implementation of the Advanced Encryption Standard (AES) encryption algorithm, utilizing a 16-byte block size. Implemented in C, this project provides a robust encryption solution suitable for various applications requiring secure data transmission and storage.

## Features

- **AES Encryption**: Utilizes the AES algorithm for secure encryption of data.
- **16-byte Block Size**: Specifically designed to operate with a 16-byte block size, ensuring compatibility and efficiency.
- **C Implementation**: Implemented in C for optimal performance and versatility.
- **Debugging Tools**: Employed tools like GDB and Valgrind for debugging and ensuring code quality.

## Components

- **encrypt.c**: This component of the program contains the main method, and it uses functionality from the other components to perform AES encryption and write out ciphertext.
- **decrypt.c**: This component of the program contains the main method, and it uses functionality from the other components to perform AES decryption and write out plaintext.
- **io.c** and **io.h**: This component handles the reading and writing of information from binary files. The header file includes majority of the documentation.
- **aes.c** and **aes.h**: This component provides the implementation of functions required to encrypt and decrypt a file, such as the generation of subkeys and the gFunction. The header file includes majority of the documentation.
- **field.c** and **field.h**: This component implements functions for addition, subtraction, and multiplication in the 8-bit Galois field used by AES. The header files includes majority of the documentation.
   
## Debugging Tools

Tools like GDB and Valgrind were utilized during the development process to ensure code correctness and optimize performance.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
