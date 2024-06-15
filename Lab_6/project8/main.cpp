#include <iostream>
#include <string>
#include <unordered_map>

using namespace std;

struct User
{
	string password;
};

unordered_map<string, User> users;



int main()
{
	setlocale(LC_ALL, "ru");
	users["user1"] = { "user1" };
	users["test"] = { "testpass" };

	string username, password;

	cout << "Имя пользователя: ";
	cin >> username;
	cout << "Пароль: ";
	cin >> password;

	if (users[username].password == password) cout << "Авторизация успешна!" << endl;
	else cout << "Неверный пароль или имя пользователя!" << endl;
}



