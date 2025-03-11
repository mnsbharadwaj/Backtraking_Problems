#include <stdio.h>
#include <stdbool.h>

void backtrack(int nums[], int used[], int path[], int n, int depth) {
    if (depth == n) {  // If all elements are used, print the permutation
        for (int i = 0; i < n; i++)
            printf("%d ", path[i]);
        printf("\n");
        return;
    }

    for (int i = 0; i < n; i++) {
        if (!used[i]) {  // Only use unused elements
            used[i] = 1;  // Mark as used
            path[depth] = nums[i];  // Choose
            backtrack(nums, used, path, n, depth + 1);  // Explore
            used[i] = 0;  // Unchoose (backtrack)
        }
    }
}

void generatePermutations(int nums[], int n) {
    int used[n];  // Boolean array to track used elements
    int path[n];  // Array to store the current permutation

    for (int i = 0; i < n; i++)
        used[i] = 0;

    backtrack(nums, used, path, n, 0);
}

int main() {
    int nums[] = {1, 2, 3};
    int n = sizeof(nums) / sizeof(nums[0]);
    generatePermutations(nums, n);
    return 0;
}
