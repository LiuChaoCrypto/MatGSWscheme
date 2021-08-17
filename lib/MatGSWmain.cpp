
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
    
	TestBootstrap_uint32();//Testing the correctness of the bootstrapping procedure.
	TestBootstrapBool_uint32();//Testing the correctness of the procedure for Boolean gates.

	// TestSecurity_uint32(MatGSWscheme,256);//Computeing the running time of MatGSWscheme and HAOscheme (by Hiromasa, Abe and Okamoto). The first input is set to be MatGSWscheme or HAOscheme, and the second input is set to be 128/192/256, which is to make clear the parameters security.
	
	 //TestSecurity_uint32(HAOscheme, 256);
	 return 0;

};
