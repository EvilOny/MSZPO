#include <string>
#include <unordered_map>
#include <iostream>
#include "checkPassword.h"


struct User
{
	std::string password;
};

std::unordered_map<std::string, User> users;
bool checkPassword(std::string username, std::string password)
{
	users["user1"] = { "user1" };
	users["test"] = { "test" };

	if (users[username].password == password) return true;
	else return false;
}




