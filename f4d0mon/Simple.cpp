#include "pch.h"
#include "Simple.h"
#include <cmath>

bool IsPrime(int n) {
	int limit = (int)::sqrt(n);
	for (int i = 2;i <= limit;i++)
		if (n % i = 0)
			return false;
	return true;
}