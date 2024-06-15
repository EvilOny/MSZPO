#include <iostream>
#include <unordered_map>
#include <winsock2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024
#define AES_KEYLEN 256
#define AES_BLOCK_SIZE 16

std::unordered_map<std::string, std::string> user_db = {
    {"user1", "password1"},
    {"user2", "password2"},
    {"user3", "password3"}
};

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

bool validate_credentials(const std::string& login, const std::string& password) {
    auto it = user_db.find(login);
    if (it != user_db.end() && it->second == password) {
        return true;
    }
    return false;
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

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        std::cerr << "Ошибка создания сокета: " << WSAGetLastError() << std::endl;
        cleanup(server_socket);
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Ошибка подключения: " << WSAGetLastError() << std::endl;
        cleanup(server_socket);
        return 1;
    }

    listen(server_socket, 3);

    std::cout << "Сервер работает на порту " << PORT << std::endl;

    SOCKET client_socket;
    sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);

    while ((client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len)) != INVALID_SOCKET) {
        unsigned char key[AES_KEYLEN / 8];
        unsigned char iv[AES_BLOCK_SIZE];
        unsigned char ciphertext[BUFFER_SIZE];
        unsigned char plaintext[BUFFER_SIZE];

        int recv_size = recv(client_socket, reinterpret_cast<char*>(key), sizeof(key), 0);
        if (recv_size == SOCKET_ERROR) {
            std::cerr << "Ошибка приёма: " << WSAGetLastError() << std::endl;
            cleanup(client_socket);
            continue;
        }

        recv_size = recv(client_socket, reinterpret_cast<char*>(iv), sizeof(iv), 0);
        if (recv_size == SOCKET_ERROR) {
            std::cerr << "Ошибка приёма: " << WSAGetLastError() << std::endl;
            cleanup(client_socket);
            continue;
        }

        recv_size = recv(client_socket, reinterpret_cast<char*>(ciphertext), sizeof(ciphertext), 0);
        if (recv_size == SOCKET_ERROR) {
            std::cerr << "Ошибка приёма: " << WSAGetLastError() << std::endl;
            cleanup(client_socket);
            continue;
        }

        int decrypted_len = decrypt(ciphertext, recv_size, key, iv, plaintext);
        if (decrypted_len == -1) {
            std::cerr << "Ошибка дешифровки." << std::endl;
            cleanup(client_socket);
            continue;
        }

        plaintext[decrypted_len] = '\0';
        std::string credentials(reinterpret_cast<char*>(plaintext));
        size_t separator = credentials.find(':');
        std::string login = credentials.substr(0, separator);
        std::string password = credentials.substr(separator + 1);

        bool is_valid = validate_credentials(login, password);
        std::string response = is_valid ? "true" : "false";

        std::cout << login << ":" << password << " " << response << std::endl;

        send(client_socket, response.c_str(), response.size(), 0);

        closesocket(client_socket);
    }

    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Ошибка приёма: " << WSAGetLastError() << std::endl;
        cleanup(server_socket);
        return 1;
    }

    cleanup(server_socket);
    return 0;
}






