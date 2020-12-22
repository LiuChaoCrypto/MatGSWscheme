
#include<iostream>

#include"MatGSWcore.h"
#include"MatGSW.h"
#include"VecLWE.h"
#include"VecLWEcore.h"
#include"LWE.h"
#include"LWEcore.h"
#include"Bootstrapcore.h"
#include"TestTime.h"
#include"TestSecurity60.h"
#include"TestBootstrap.h"


using namespace std;

int main() {

	

	//TestSecurity60_uint16(MatMulMat);
	
	TestBootstrap_uint32();
	TestSecurity_uint32(MatGSWscheme,256);
	return 0;

};