#include <Windows.h>
#include <iostream>
#include <assert.h>

int main()
{
	auto hTestModule = LoadLibraryA("TestDll.dll");
	assert(hTestModule);


	getchar();
	return 0;
}

