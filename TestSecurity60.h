#pragma once
#ifndef TESTSECURITY60
#define TESTSECURITY60

enum Method{HAOscheme, MatGSWscheme};
void TestSecurity60_uint16(Method);

void TestSecurity128_uint16(Method);



void TestSecurity_uint32(Method,int security);
#endif // !TESTSECURITY60
