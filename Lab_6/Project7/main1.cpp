#include <iostream>
#include <string>
#include <unordered_map>
#include "../checkPassword/checkPassword.h"

using namespace std;

int main()
{
	setlocale(LC_ALL, "ru");

	string username, password;

	cout << "Имя пользователя: ";
	cin >> username;
	cout << "Пароль: ";
	cin >> password;

	if (checkPassword(username, password)) cout << "Авторизация успешна!" << endl;
	else cout << "Неверный пароль или имя пользователя!" << endl;
}



