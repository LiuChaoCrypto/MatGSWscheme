#pragma once
#ifndef TESTSECURITY60
#define TESTSECURITY60

enum Method{HAOscheme, MatGSWscheme};
void TestSecurity60_uint16(Method);//60 bit security, Q=2^16

void TestSecurity128_uint16(Method);//128 bit security, Q=2^16



void TestSecurity_uint32(Method,int security);//Q=2^32
#endif // !TESTSECURITY60
