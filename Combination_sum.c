#include <stdio.h>

void backtrack(int candidates[], int n, int target, int start, int path[], int pathLen) {
    if (target == 0) {  // If sum matches target, print combination
        for (int i = 0; i < pathLen; i++)
            printf("%d ", path[i]);
        printf("\n");
        return;
    }

    for (int i = start; i < n; i++) {
        if (candidates[i] > target)  // Skip if larger than target
            continue;

        path[pathLen] = candidates[i];  // Choose
        backtrack(candidates, n, target - candidates[i], i, path, pathLen + 1);  // Explore
    }
}

void combinationSum(int candidates[], int n, int target) {
    int path[target];  // To store current combination
    backtrack(candidates, n, target, 0, path, 0);
}

int main() {
    int candidates[] = {2, 3, 6, 7};
    int target = 7;
    int n = sizeof(candidates) / sizeof(candidates[0]);

    combinationSum(candidates, n, target);
    return 0;
}
