int main() {
    char password[32] = "super_secret_123";
    char user_input[100];
    int uninit_var;
    int calculated = uninit_var + 10;
    
    gets(user_input);
    printf(user_input);
    strcpy(user_input, "dangerous");
    return 0;
}
