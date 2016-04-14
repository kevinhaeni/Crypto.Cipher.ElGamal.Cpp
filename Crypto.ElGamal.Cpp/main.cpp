#include "stdafx.h"
#include <iostream>
#include "ElGamal.h"

int _tmain(int argc, _TCHAR* argv[])
{
	
	auto keys = ElGamal::keyGen();
	auto pk = keys.first;
	auto sk = keys.second;

	Int msg = 3;
	std::cout << "Message = " << msg << std::endl;

	auto C = ElGamal::encrypt(pk, msg);
	std::cout << "Ciphertext = " << C.second << std::endl;

	Int m = ElGamal::decrypt(sk, C);
	std::cout << "Decrypted m = " << m << std::endl;

	int i;
	std::cin >> i;
	return 0;
}

