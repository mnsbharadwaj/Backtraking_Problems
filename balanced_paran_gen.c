#include <stdio.h>

void backtrack(char path[], int pos, int open, int close, int n) {
    if (pos == 2 * n) {  // If valid sequence is complete
        path[pos] = '\0';
        printf("%s\n", path);
        return;
    }

    if (open < n) {  // Add '(' if possible
        path[pos] = '(';
        backtrack(path, pos + 1, open + 1, close, n);
    }

    if (close < open) {  // Add ')' if valid
        path[pos] = ')';
        backtrack(path, pos + 1, open, close + 1, n);
    }
}

void generateParentheses(int n) {
    char path[2 * n + 1];
    backtrack(path, 0, 0, 0, n);
}

int main() {
    int n = 3;
    generateParentheses(n);
    return 0;
}
