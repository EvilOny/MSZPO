#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <winsock2.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 4096

void initialize_winsock() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "Ошибка иннициализации WinSock: " << WSAGetLastError() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void initialize_openssl() {
    OPENSSL_init_crypto(0, NULL);
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

EVP_PKEY* createEVPKeyFromFile(const char* filename, bool isPublic) {
    FILE* fp = fopen(filename, "rb");
    if (fp == nullptr) {
        std::cerr << "Невозможно открыть файл " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY* evp_pkey = nullptr;
    if (isPublic) {
        evp_pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    }
    else {
        evp_pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    }

    fclose(fp);
    return evp_pkey;
}

int main() {
    setlocale(LC_ALL, "ru");
    initialize_winsock();
    initialize_openssl();

    EVP_PKEY* publicKey = createEVPKeyFromFile("public_key.pem", true);
    if (publicKey == nullptr) {
        std::cerr << "Ошибка чтения публичного ключа." << std::endl;
        return 1;
    }

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

    std::string login, password;
    std::cout << "Логин: ";
    std::cin >> login;
    std::cout << "Пароль: ";
    std::cin >> password;

    std::string credentials = login + ":" + password;
    unsigned char encrypted_data[BUFFER_SIZE];

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
    if (!ctx) {
        std::cerr << "Ошибка создания контекста: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        cleanup(client_socket);
        return 1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Ошибка ининицализации контекста: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        cleanup(client_socket);
        return 1;
    }

    size_t encrypted_len;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encrypted_len, reinterpret_cast<const unsigned char*>(credentials.c_str()), credentials.size()) <= 0) {
        std::cerr << "Ошибка шифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        cleanup(client_socket);
        return 1;
    }

    if (EVP_PKEY_encrypt(ctx, encrypted_data, &encrypted_len, reinterpret_cast<const unsigned char*>(credentials.c_str()), credentials.size()) <= 0) {
        std::cerr << "Ошибка шифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        cleanup(client_socket);
        return 1;
    }

    send(client_socket, reinterpret_cast<const char*>(encrypted_data), encrypted_len, 0);

    char response[BUFFER_SIZE];
    int recv_size = recv(client_socket, response, BUFFER_SIZE, 0);
    if (recv_size == SOCKET_ERROR) {
        std::cerr << "Ошибка получения информации: " << WSAGetLastError() << std::endl;
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

    EVP_PKEY_free(publicKey);
    cleanup(client_socket);
    return 0;
}





