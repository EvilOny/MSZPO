#include <iostream>
#include <map>
#include <string>
#include "md5.h"
#include "obfuscator.hpp"

using namespace std;
using namespace obfs;

template <char key>
constexpr char xor_(char c) {
	return c ^ key;
}

template <char Key>
constexpr char add(char c) {
	return c + Key;
}

template <char(*f)(char), char(*g)(char)>
constexpr char comp(char c) {
	return f(g(c));
}

void method_1()
{
	using table = obfs::make_table<
		obfs::encoder_seq<xor_<0x50>, add<10>, comp<xor_<0x50>, add<10>>>,
		obfs::decoder_seq<xor_<0x50>, add<-10>, comp<add<-10>, xor_<0x50>>>>;

	MAKE_STRING(correctuser, "user", table);
	MAKE_STRING(correctpass, "password", table);
	MAKE_STRING(str1, "Логин: ", table);
	MAKE_STRING(str2, "Пароль: ", table);
	MAKE_STRING(str3, "Успешная авторизация!", table);
	MAKE_STRING(str4, "Неверный логин или пароль!", table);

	string user;
	string pass;

	cout << str1.decode();
	cin >> user;
	cout << str2.decode();
	cin >> pass;
	if (correctuser.decode() == user && correctpass.decode() == pass) cout << str3.decode() << endl;
	else cout << str4.decode() << endl;
}

void method_2()
{
	int correctuser = 252;
	int correctpass = 920;
	string user;
	string pass;
	map <char, int> alphabet;
	alphabet['a'] = 1;
	alphabet['b'] = 2;
	alphabet['c'] = 3;
	alphabet['d'] = 4;
	alphabet['e'] = 5;
	alphabet['f'] = 6;
	alphabet['g'] = 7;
	alphabet['h'] = 8;
	alphabet['i'] = 9;
	alphabet['j'] = 10;
	alphabet['k'] = 11;
	alphabet['l'] = 12;
	alphabet['m'] = 13;
	alphabet['n'] = 14;
	alphabet['o'] = 15;
	alphabet['p'] = 16;
	alphabet['q'] = 17;
	alphabet['r'] = 18;
	alphabet['s'] = 19;
	alphabet['t'] = 20;
	alphabet['u'] = 21;
	alphabet['v'] = 22;
	alphabet['w'] = 23;
	alphabet['x'] = 24;
	alphabet['y'] = 25;
	alphabet['z'] = 26;

	int user_int = 0;
	int pass_int = 0;

	cout << "Логин: ";
	cin >> user;
	cout << "Пароль: ";
	cin >> pass;

	for (int i = 0; i < size(user); i++)
	{
		user_int += alphabet[user[i]] * size(user);
	}
	for (int i = 0; i < size(pass); i++)
	{
		pass_int += alphabet[pass[i]] * size(pass);
	}

	if (correctuser == user_int && correctpass == pass_int) cout << "Успешная авторизация!" << endl;
	else cout << "Неверный логин или пароль!" << endl;
}

void method_3()
{
	string correctuser = md5("user");
	string correctpass = md5("password");
	string user;
	string pass;

	cout << "Логин: ";
	cin >> user;
	cout << "Пароль: ";
	cin >> pass;

	if (correctuser == md5(user) && correctpass == md5(pass)) cout << "Успешная авторизация!" << endl;
	else cout << "Неверный логин или пароль!" << endl;
}

void method_4()
{

}

void menu()
{
	int method;

	cout << "Выберите необходимый метод авторизации:\n1. Сравнение в открытом виде\n2. Перевод символов в числа\n3. MD5\n4. Перемешивание по заданному алгоритму" << endl;
	cin >> method;

	switch (method)
	{
	case 1:
		system("cls");
		method_1();
		break;
	case 2:
		system("cls");
		method_2();
		break;
	case 3:
		system("cls");
		method_3();
		break;
	case 4:
		system("cls");
		method_4();
		break;
	default:
		cout << "Выбранного пункта нет в списке!" << endl;
		break;
	}

}

int main()
{
	setlocale(LC_ALL, "ru");

	bool flag = true;
	while (flag)
	{
		menu();
		cout << "0. Завершить выполнение программы\n1. Выбрать другой метод аутентиикации" << endl;
		cin >> flag;
		if (flag != 1) break;
		system("cls");
	}
}