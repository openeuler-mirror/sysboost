#include <stdio.h>

extern void foo(void);
extern const char *exported_str;

const char * const message = "Test for local const variables.\n";

int test_local_function(){
    printf("Test for local function.\n");
    return 0;
}

int main(){
    foo();
    printf("Test for functions in unmerged .so file.\n");
    printf("%s", exported_str);
    printf("%s", message);
    test_local_function();
    return 0;
}