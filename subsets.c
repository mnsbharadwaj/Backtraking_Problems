#include <stdio.h>

void backtrack(int nums[], int n, int start, int path[], int depth) {
    printf("{ ");
    for (int i = 0; i < depth; i++)
        printf("%d ", path[i]);
    printf("}\n");

    for (int i = start; i < n; i++) {
        path[depth] = nums[i];  // Choose
        backtrack(nums, n, i + 1, path, depth + 1);  // Explore
    }
}

void generateSubsets(int nums[], int n) {
    int path[n];  // Storage for subset
    backtrack(nums, n, 0, path, 0);
}

int main() {
    int nums[] = {1, 2, 3};
    int n = sizeof(nums) / sizeof(nums[0]);
    generateSubsets(nums, n);
    return 0;
}
