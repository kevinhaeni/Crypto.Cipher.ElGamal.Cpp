#pragma once

#include "Algorithms.h"

#define _CRT_SECURE_NO_WARNINGS

typedef std::pair<Int, Int> Group;


class ElGamal{
public:
	static std::pair<std::pair<Int, Group>, std::pair<Int, Group>> keyGen();

	static std::pair<Int, Int> encrypt(std::pair<Int, Group> pk, Int message);
	static Int decrypt(std::pair<Int, Group> sk, std::pair<Int, Int> c);

};