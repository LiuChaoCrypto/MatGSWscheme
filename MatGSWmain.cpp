
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
    //Testing the correctness of the bootstrapping procedure.
	TestBootstrap_uint32();
    //Computeing the time complexity of HAOscheme and MatGSWscheme.
    //The first input (MatGSWscheme/HAOscheme) is to make clear the type of the scheme. The second input (128/192/256) is to make clear the params. 
	TestSecurity_uint32(MatGSWscheme,256);
	return 0;

};
