# Advanced Encryption Standard (AES) Project

This repository hosts an implementation of the Advanced Encryption Standard (AES) encryption algorithm, utilizing a 16-byte block size. Implemented in C, this project provides a robust encryption solution suitable for various applications requiring secure data transmission and storage.

## Features

- **AES Encryption**: Utilizes the AES algorithm for secure encryption of data.
- **16-byte Block Size**: Specifically designed to operate with a 16-byte block size, ensuring compatibility and efficiency.
- **C Implementation**: Implemented in C for optimal performance and versatility.
- **Debugging Tools**: Employed tools like GDB and Valgrind for debugging and ensuring code quality.

## Usage

1. **Clone the Repository**: Clone this repository to your local machine.
   ```bash
   git clone https://github.com/your-username/AdvancedEncryptionStandardProject.git
   ```

2. **Build**: Compile the source code using the Makefile to generate the executable.
   ```bash
   make
   ```

3. **Encrypt Data**: Utilize the executable to encrypt your data.
   ```bash
   ./aes encrypt <input_file> <output_file>
   ```

4. **Decrypt Data**: Decrypt encrypted data using the executable.
   ```bash
   ./aes decrypt <input_file> <output_file>
   ```
   
## Debugging Tools

Tools like GDB and Valgrind were utilized during the development process to ensure code correctness and optimize performance.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
