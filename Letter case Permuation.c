#include <stdio.h>
#include <ctype.h>
#include <string.h>

void backtrack(char str[], int index) {
    if (str[index] == '\0') {  // Base case: print permutation
        printf("%s\n", str);
        return;
    }

    backtrack(str, index + 1);  // Continue with the same letter

    if (isalpha(str[index])) {  // If letter, change case
        str[index] ^= 32;  // Toggle case
        backtrack(str, index + 1);
        str[index] ^= 32;  // Restore original
    }
}

int main() {
    char str[] = "a1b";
    backtrack(str, 0);
    return 0;
}
