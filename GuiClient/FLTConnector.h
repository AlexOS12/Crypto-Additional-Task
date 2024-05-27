#pragma once

#ifdef FLTCONNECTOR_EXPORTS
#define FLTCONNECTOR_API __declspec(dllexport)
#else
#define FLTCONNECTOR_API
#endif

extern "C" FLTCONNECTOR_API __declspec(dllexport) int test(int a, int b);