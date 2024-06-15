#include <iostream>
#include <string>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

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

int main() {
    initialize_winsock();
    setlocale(LC_ALL, "ru");

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
    std::cout << "Имя пользователя: ";
    std::cin >> login;
    std::cout << "Пароль: ";
    std::cin >> password;

    std::string credentials = login + ":" + password;
    send(client_socket, credentials.c_str(), credentials.size(), 0);

    char response[BUFFER_SIZE];
    int recv_size = recv(client_socket, response, BUFFER_SIZE, 0);
    if (recv_size == SOCKET_ERROR) {
        std::cerr << "Ошибка получения информации через сокет: " << WSAGetLastError() << std::endl;
        cleanup(client_socket);
        return 1;
    }

    response[recv_size] = '\0';
    std::string result(response);

    if (result == "true") {
        std::cout << "Усешная авторизация." << std::endl;
    }
    else {
        std::cout << "Неправильный логин или пароль." << std::endl;
    }

    cleanup(client_socket);
    return 0;
}
