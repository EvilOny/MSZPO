#include <iostream>
#include <unordered_map>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

std::unordered_map<std::string, std::string> user_db = {
    {"user1", "password1"},
    {"user2", "password2"},
    {"user3", "password3"}
};

void initialize_winsock() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "Ошибка инициализации WinSock2: " << WSAGetLastError() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void cleanup(SOCKET socket) {
    closesocket(socket);
    WSACleanup();
}

bool validate_credentials(const std::string& login, const std::string& password) {
    auto it = user_db.find(login);
    if (it != user_db.end() && it->second == password) {
        return true;
    }
    return false;
}

int main() {
    initialize_winsock();
    setlocale(LC_ALL, "ru");

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        std::cerr <<"Не удалось создать сокет: " << WSAGetLastError() << std::endl;
        cleanup(server_socket);
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Ошибка бинда: " << WSAGetLastError() << std::endl;
        cleanup(server_socket);
        return 1;
    }

    listen(server_socket, 3);
    std::cout << "Сервер поднят и работает на порту " << PORT << std::endl;
    SOCKET client_socket;
    sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);

    while ((client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len)) != INVALID_SOCKET) {
        char buffer[BUFFER_SIZE];
        int recv_size = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (recv_size == SOCKET_ERROR) {
            std::cerr << "Ошибка получения информации через сокет: " << WSAGetLastError() << std::endl;
            cleanup(client_socket);
            continue;
        }

        buffer[recv_size] = '\0';
        std::string credentials(buffer);
        size_t separator = credentials.find(':');
        std::string login = credentials.substr(0, separator);
        std::string password = credentials.substr(separator + 1);

        bool is_valid = validate_credentials(login, password);
        std::string response = is_valid ? "true" : "false";
        std::cout << login << ":" << password << " = " << response << std::endl;
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
