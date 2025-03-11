#include <stdio.h>

void backtrack(int start, int n, int k, int path[], int depth) {
    if (depth == k) {  // If k elements are selected, print them
        for (int i = 0; i < k; i++)
            printf("%d ", path[i]);
        printf("\n");
        return;
    }

    for (int i = start; i <= n; i++) {
        path[depth] = i;  // Choose
        backtrack(i + 1, n, k, path, depth + 1);  // Explore
    }
}

void generateCombinations(int n, int k) {
    int path[k];  // Array to store the current combination
    backtrack(1, n, k, path, 0);
}

int main() {
    int n = 4, k = 2;
    generateCombinations(n, k);
    return 0;
}
