#include "ElGamal.h"
#include <boost/math/common_factor_rt.hpp>

typedef std::pair<Int, Int> Group;

/**
* Generates a pk (public key) and sk (private / secret key) pair and the group parameters G(p,g) with modulus p and generator g
* returns: pk(a, G)   and    sk(A, G)       of type std::pair
*/
std::pair<std::pair<Int, Group>, std::pair<Int, Group>> ElGamal::keyGen(){
	Algorithms::seedRNG();

	// generate public parameters
	Int p = Algorithms::randomSafePrime<128>(10);		// generate a 128 bit safe-prime
	Int q = (p-1) / 2;									// p/2-1 is the order of the subgroup q

	Int g = 0;											// get a random generator of <G>
	for (;;){
		g = Algorithms::getRandomNumber(2, p-1);		// get a random number 1 < g < p-1
		if (boost::math::gcd(g, q) == 1)				// must be an elment of Zp*
		{
			if (powm(g, q, p) == 1)						// check if g^q mod p = 1 (if the element is a generator of subgroup G)
				break;
		}			
	}
	Group G = std::make_pair(p, g);						// <G> = (p, g)

	// private key a
	Int a = 0;
	for (;;){
		a = Algorithms::getRandomNumber(2, p-1);
		Int gcd = boost::math::gcd(a, p);
		if (gcd == 1)
			break;
	}

	std::pair<Int, Group> sk = std::make_pair(a, G);

	// public key A
	Int A = powm(g, a, p);
	std::pair<Int, Group> pk = std::make_pair(A, G);


#ifdef _DEBUG
	std::cout << "Safeprime p = " << p << std::endl;
	std::cout << "q as (p-1/2) = " << q << std::endl;
	std::cout << "Generator g = " << g << std::endl;
	std::cout << "Private key a = " << a << std::endl;
	std::cout << "Public key A = " << A << std::endl;
#endif

	return std::make_pair(pk, sk);
}

std::pair<Int, Int> ElGamal::encrypt(std::pair<Int, Group> pk, Int message){
	Int A = pk.first;
	Group G = pk.second;	
	Int p = G.first;
	Int g = G.second;

	// random b
	Int b = 0;
	for (;;){
		b = Algorithms::getRandomNumber(2, p - 1);
		Int gcd = boost::math::gcd(b, p);
		if (gcd == 1)
			break;
	}
	Int B = powm(g, b, p);
	
	// encryption

	Int c = powm(A, b, p);
	c *= message;
	c %= p;

#ifdef _DEBUG
	std::cout << "b = " << b << std::endl;
	std::cout << "B = " << B << std::endl;
#endif

	return std::make_pair(B, c);	// (B,c)
}

// takes sk, (B,c)
Int ElGamal::decrypt(std::pair<Int, Group> sk, std::pair<Int,Int> C){	
	Int c = C.second;
	Int B = C.first;	
	
	Int a = sk.first;
	Group G = sk.second;

	Int p = G.first;
	Int g = G.second;

	Int ainv = Algorithms::modInverse(B, p);
#ifdef _DEBUG
	std::cout << "ainv = " << ainv << std::endl;
#endif
	//Int m = powm(B, ainv, p);
	Int m = powm(ainv, a, p);
	m *= c;
	m %= p;
	// m = B^-a * ciphertext mod p

	return m;
	//return powm(ciphertext, sk.second, sk.first);
}