#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <unordered_map>
#include <winsock2.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "crypt32.lib")

#define PORT 8080
#define BUFFER_SIZE 4096
#define TIMEOUT_SECONDS 30

std::unordered_map<std::string, std::string> user_db = {
    {"user1", "password1"},
    {"user2", "password2"},
    {"user3", "password3"}
};

void initialize_winsock() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "Ошибка инициализации WinSock: " << WSAGetLastError() << std::endl;
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
        std::cerr << "Ошибка открытия файла " << filename << std::endl;
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

bool validate_credentials(const std::string& login, const std::string& password) {
    auto it = user_db.find(login);
    if (it != user_db.end() && it->second == password) {
        return true;
    }
    return false;
}

bool verify_hash(const std::string& data, const unsigned char* received_hash) {
    unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), calculated_hash);
    return memcmp(calculated_hash, received_hash, SHA256_DIGEST_LENGTH) == 0;
}

int main() {
    setlocale(LC_ALL, "ru");
    initialize_winsock();
    initialize_openssl();

    EVP_PKEY* privateKey = createEVPKeyFromFile("private_key.pem", false);
    if (privateKey == nullptr) {
        std::cerr << "Ошибка загрузки приватного ключа." << std::endl;
        return 1;
    }

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
        std::cerr << "Ошибка привязки: " << WSAGetLastError() << std::endl;
        cleanup(server_socket);
        return 1;
    }

    listen(server_socket, 3);

    std::cout << "Сервер запущен и работает на порту " << PORT << std::endl;

    SOCKET client_socket;
    sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);

    while ((client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len)) != INVALID_SOCKET) {
        unsigned char encrypted_data[BUFFER_SIZE];
        int recv_size = recv(client_socket, reinterpret_cast<char*>(encrypted_data), sizeof(encrypted_data), 0);
        if (recv_size == SOCKET_ERROR) {
            std::cerr << "Ошибка получения информации: " << WSAGetLastError() << std::endl;
            cleanup(client_socket);
            continue;
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx) {
            std::cerr << "Ошибка создания контекста: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            cleanup(client_socket);
            continue;
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            std::cerr << "Ошибка инициализации контекста: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            EVP_PKEY_CTX_free(ctx);
            cleanup(client_socket);
            continue;
        }

        size_t decrypted_len;
        if (EVP_PKEY_decrypt(ctx, nullptr, &decrypted_len, encrypted_data, recv_size) <= 0) {
            std::cerr << "Ошибка дешифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            EVP_PKEY_CTX_free(ctx);
            cleanup(client_socket);
            continue;
        }

        unsigned char* decrypted_data = new unsigned char[decrypted_len];
        if (EVP_PKEY_decrypt(ctx, decrypted_data, &decrypted_len, encrypted_data, recv_size) <= 0) {
            std::cerr << "Ошибка дешифрования: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            EVP_PKEY_CTX_free(ctx);
            delete[] decrypted_data;
            cleanup(client_socket);
            continue;
        }

        EVP_PKEY_CTX_free(ctx);

        unsigned char received_hash[SHA256_DIGEST_LENGTH];
        memcpy(received_hash, decrypted_data, SHA256_DIGEST_LENGTH);
        std::time_t sent_time;
        memcpy(&sent_time, decrypted_data + SHA256_DIGEST_LENGTH, sizeof(sent_time));
        std::string credentials(reinterpret_cast<char*>(decrypted_data + SHA256_DIGEST_LENGTH + sizeof(sent_time)), decrypted_len - SHA256_DIGEST_LENGTH - sizeof(sent_time));
        delete[] decrypted_data;

        std::time_t received_time = std::time(nullptr);
        if (received_time - sent_time > TIMEOUT_SECONDS) {
            std::cerr << "Временные метки не совпадают!" << std::endl;
            cleanup(client_socket);
            continue;
        }

        if (!verify_hash(credentials, received_hash)) {
            std::cerr << "Неудалось верифицировать хэш сообщения!" << std::endl;
            cleanup(client_socket);
            continue;
        }

        size_t separator = credentials.find(':');
        std::string login = credentials.substr(0, separator);
        std::string password = credentials.substr(separator + 1);

        bool is_valid = validate_credentials(login, password);
        std::string response = is_valid ? "true" : "false";

        std::cout << login << ":" << password << " " << response << std::endl;
        std::cout << received_hash << std::endl;

        send(client_socket, response.c_str(), response.size(), 0);

        closesocket(client_socket);
    }

    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Ошибка приёма: " << WSAGetLastError() << std::endl;
        cleanup(server_socket);
        return 1;
    }

    EVP_PKEY_free(privateKey);
    cleanup(server_socket);
    return 0;
}
