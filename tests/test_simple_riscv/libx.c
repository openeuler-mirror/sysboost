#include <stdio.h>

void foo()
{
    printf("Test for functions in the merged .so file.\n");
}

const char * const exported_str = "Test for the use of external variables.\n";