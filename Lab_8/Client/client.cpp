#include <iostream>
#include <string>
#include <winsock2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024
#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16

void initialize_winsock() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "Ошибка инициализации: " << WSAGetLastError() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

void cleanup(SOCKET socket) {
    closesocket(socket);
    WSACleanup();
    cleanup_openssl();
}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main() {
    setlocale(LC_ALL, "ru");
    initialize_winsock();
    initialize_openssl();

    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Ошибка создания сокета: " << WSAGetLastError() << std::endl;
        cleanup(client_socket);
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);

    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Ошибка подключения: " << WSAGetLastError() << std::endl;
        cleanup(client_socket);
        return 1;
    }

    unsigned char key[AES_KEYLEN / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Ошибка генерации рандомных ключей" << std::endl;
        cleanup(client_socket);
        return 1;
    }

    std::string login, password;
    std::cout << "Логин: ";
    std::cin >> login;
    std::cout << "Пароль: ";
    std::cin >> password;

    std::string credentials = login + ":" + password;
    unsigned char ciphertext[BUFFER_SIZE];

    int ciphertext_len = encrypt(const_cast<unsigned char*>((unsigned char*)credentials.data()), credentials.size(), key, iv, ciphertext);
    if (ciphertext_len == -1) {
        std::cerr << "Ошибка шифрования." << std::endl;
        cleanup(client_socket);
        return 1;
    }

    send(client_socket, reinterpret_cast<const char*>(key), sizeof(key), 0);
    send(client_socket, reinterpret_cast<const char*>(iv), sizeof(iv), 0);
    send(client_socket, reinterpret_cast<const char*>(ciphertext), ciphertext_len, 0);

    char response[BUFFER_SIZE];

    int recv_size = recv(client_socket, response, BUFFER_SIZE, 0);
    if (recv_size == SOCKET_ERROR) {
        std::cerr << "Ошибка получения: " << WSAGetLastError() << std::endl;
        cleanup(client_socket);
        return 1;
    }

    response[recv_size] = '\0';
    std::string result(response);

    if (result == "true") {
        std::cout << "Успешная авторизация." << std::endl;
    }
    else {
        std::cout << "Неверный логин или пароль." << std::endl;
    }

    cleanup(client_socket);
    return 0;
}

