#include <iostream>
#include <string>
#include <unordered_map>
#include "../checkPassword/checkPassword.h"

using namespace std;

int main()
{
	setlocale(LC_ALL, "ru");

	string username, password;

	cout << "��� ������������: ";
	cin >> username;
	cout << "������: ";
	cin >> password;

	if (checkPassword(username, password)) cout << "����������� �������!" << endl;
	else cout << "�������� ������ ��� ��� ������������!" << endl;
}



