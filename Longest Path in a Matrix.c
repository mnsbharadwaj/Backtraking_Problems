/*Find the longest increasing path in an N x M matrix where adjacent moves are only allowed in 4 directions.*/
#include <stdio.h>
#include <stdlib.h>

#define N 3
#define M 3

int moves[4][2] = {{1, 0}, {0, 1}, {-1, 0}, {0, -1}};  // Down, Right, Up, Left

int isSafe(int x, int y, int prev, int mat[N][M]) {
    return (x >= 0 && x < N && y >= 0 && y < M && mat[x][y] > prev);
}

int findLongestPath(int mat[N][M], int x, int y, int dp[N][M]) {
    if (dp[x][y] != -1)
        return dp[x][y];

    int maxLength = 1;

    for (int i = 0; i < 4; i++) {
        int nextX = x + moves[i][0];
        int nextY = y + moves[i][1];

        if (isSafe(nextX, nextY, mat[x][y], mat)) {
            int length = 1 + findLongestPath(mat, nextX, nextY, dp);
            if (length > maxLength)
                maxLength = length;
        }
    }

    return dp[x][y] = maxLength;
}

int longestIncreasingPath(int mat[N][M]) {
    int dp[N][M];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < M; j++)
            dp[i][j] = -1;

    int maxPath = 1;
    for (int i = 0; i < N; i++)
        for (int j = 0; j < M; j++)
            if (dp[i][j] == -1)
                maxPath = fmax(maxPath, findLongestPath(mat, i, j, dp));

    return maxPath;
}

int main() {
    int mat[N][M] = {
        {9, 9, 4},
        {6, 6, 8},
        {2, 1, 1}
    };

    printf("Longest Path Length: %d\n", longestIncreasingPath(mat));
    return 0;
}
