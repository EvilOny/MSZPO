#include <iostream>
#include <unordered_map>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <conio.h>
#include <algorithm>
#include "md5.h"

struct User {
    std::string password;
    bool isBlocked = false;
    bool passwordRestrictions = false;
};

std::string adminPassword = md5("admin");

std::unordered_map<std::string, User> users;

const std::string usersFile = "users.txt";

void loadUsersFromFile() {
    std::ifstream file(usersFile);
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string username, password;
        bool isBlocked, passwordRestrictions;
        iss >> username;
        if (iss.peek() == ' ') iss.ignore();
        std::getline(iss, password, ' ');
        iss >> isBlocked >> passwordRestrictions;
        users[username] = { password, isBlocked, passwordRestrictions };
    }
}

void saveUsersToFile() {
    std::ofstream file(usersFile);
    for (const auto& pair : users) {
        file << pair.first << " " << pair.second.password << " "
            << pair.second.isBlocked << " " << pair.second.passwordRestrictions << "\n";
    }
}

std::string inputPassword() {
    std::string password;
    char ch;
    while ((ch = _getch()) != 13) {
        if (ch == 8 && !password.empty()) {
            std::cout << "\b \b";
            password.pop_back();
        }
        else if (ch != 8) {
            std::cout << '*';
            password.push_back(ch);
        }
    }
    std::cout << std::endl;
    return password;
}

bool changePassword(const std::string& username) {
    std::cout << "Введите старый пароль: ";
    std::string oldPassword = inputPassword();
    if (users[username].password == md5(oldPassword)) {
        std::string newPassword, confirmPassword;
        std::cout << "Новый пароль: ";
        newPassword = inputPassword();
        std::cout << "Повторите новый пароль: ";
        confirmPassword = inputPassword();
        if (newPassword == confirmPassword) {
            if (users[username].passwordRestrictions && newPassword.length() < 6) {
                std::cout << "Минимальная длина пароля - 6 символов.\n";
                return false;
            }
            users[username].password = md5(newPassword);
            saveUsersToFile();
            std::cout << "Пароль изменён.\n";
            return true;
        }
        else {
            std::cout << "Пароли не совпадают.\n";
        }
    }
    else {
        std::cout << "Неправильный старый пароль.\n";
    }
    return false;
}

void setInitialPassword(const std::string& username) {
    std::string newPassword, confirmPassword;
    std::cout << "Новый пароль: ";
    newPassword = inputPassword();
    std::cout << "Повторите новый пароль: ";
    confirmPassword = inputPassword();
    if (newPassword == confirmPassword) {
        if (users[username].passwordRestrictions && newPassword.length() < 6) {
            std::cout << "Минимальная длина пароля - 6 символов.\n";
            setInitialPassword(username);
        }
        else {
            users[username].password = md5(newPassword);
            saveUsersToFile();
            std::cout << "Пароль изменён.\n";
        }
    }
    else {
        std::cout << "Пароли не совпадают.\n";
        setInitialPassword(username);
    }
}

void displayAllUsers() {
    for (const auto& pair : users) {
        std::cout << "Имя: " << pair.first << ", Блокировка: " << pair.second.isBlocked
            << ", Парольная политика: " << pair.second.passwordRestrictions << "\n";
    }
}

void addUser(const std::string& username) {
    if (users.find(username) == users.end()) {
        users[username] = { "", false, false };
        saveUsersToFile();
        std::cout << "Пользователь добавлен.\n";
    }
    else {
        std::cout << "Пользователь уже существует.\n";
    }
}

void blockUser(const std::string& username) {
    if (users.find(username) != users.end()) {
        users[username].isBlocked = !users[username].isBlocked;
        saveUsersToFile();
        std::cout << "Пользователь заблокирован.\n";
    }
    else {
        std::cout << "Пользователь не существует.\n";
    }
}

void togglePasswordRestrictions(const std::string& username) {
    if (users.find(username) != users.end()) {
        users[username].passwordRestrictions = !users[username].passwordRestrictions;
        saveUsersToFile();
        std::cout << "Ограничения включены.\n";
    }
    else {
        std::cout << "Пользователь не существует.\n";
    }
}

void adminFunctions() {
    while (true) {
        std::cout << "1. Смена пароля\n";
        std::cout << "2. Список пользователей\n";
        std::cout << "3. Добавить нового пользователя\n";
        std::cout << "4. Заблокировать пользователя\n";
        std::cout << "5. Ограничить пароль пользователя\n";
        std::cout << "6. Выход\n";
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        if (choice == 1) {
            changePassword("admin");
        }
        else if (choice == 2) {
            displayAllUsers();
        }
        else if (choice == 3) {
            std::string username;
            std::cout << "Имя пользователя: ";
            std::getline(std::cin, username);
            addUser(username);
        }
        else if (choice == 4) {
            std::string username;
            std::cout << "Имя пользователя: ";
            std::getline(std::cin, username);
            blockUser(username);
        }
        else if (choice == 5) {
            std::string username;
            std::cout << "Имя пользователя: ";
            std::getline(std::cin, username);
            togglePasswordRestrictions(username);
        }
        else if (choice == 6) {
            break;
        }
    }
}

void userFunctions(const std::string& username) {
    while (true) {
        std::cout << "1. Смена пароля\n";
        std::cout << "2. Выход\n";
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        if (choice == 1) {
            changePassword(username);
        }
        else if (choice == 2) {
            break;
        }
    }
}

int main() {
    setlocale(LC_ALL, "ru");

    loadUsersFromFile();
    while (true) {
        std::string username, password;
        std::cout << "Имя пользователя: ";
        std::getline(std::cin, username);
        std::cout << "Пароль: ";
        password = inputPassword();
        if (username == "admin" && md5(password) == adminPassword) {
            adminFunctions();
        }
        else if (users.find(username) != users.end()) {
            if (users[username].isBlocked) {
                std::cout << "Пользователь заблокирован.\n";
            }
            else if (users[username].password.empty()) {
                std::cout << "Вам необходимо задать новый пароль.\n";
                setInitialPassword(username);
            }
            else if (users[username].password == md5(password)) {
                userFunctions(username);
            }
            else {
                std::cout << "Неверный пароль.\n";
            }
        }
        else {
            std::cout << "Пользователь не существует.\n";
        }
    }
    return 0;
}
