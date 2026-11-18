#include <iostream>
#include <string>

using namespace std;

int main() {
    char token[32] = "secret_cpp_token";
    char buffer[64];
    int* mem = new int[100];

    gets(buffer);
    printf(buffer);
    return 0;
}
