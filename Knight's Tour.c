#include <stdio.h>

#define N 8
int moves[8][2] = {{2, 1}, {1, 2}, {-1, 2}, {-2, 1}, {-2, -1}, {-1, -2}, {1, -2}, {2, -1}};

void printBoard(int board[N][N]) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++)
            printf("%2d ", board[i][j]);
        printf("\n");
    }
}

int isSafe(int x, int y, int board[N][N]) {
    return (x >= 0 && x < N && y >= 0 && y < N && board[x][y] == -1);
}

int solveKnightTour(int x, int y, int moveCount, int board[N][N]) {
    if (moveCount == N * N) return 1;  // All squares visited

    for (int i = 0; i < 8; i++) {
        int nextX = x + moves[i][0];
        int nextY = y + moves[i][1];

        if (isSafe(nextX, nextY, board)) {
            board[nextX][nextY] = moveCount;

            if (solveKnightTour(nextX, nextY, moveCount + 1, board))
                return 1;

            board[nextX][nextY] = -1;  // Backtrack
        }
    }
    return 0;
}

void knightTour() {
    int board[N][N];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            board[i][j] = -1;

    board[0][0] = 0;  // Start position

    if (solveKnightTour(0, 0, 1, board))
        printBoard(board);
    else
        printf("Solution does not exist\n");
}

int main() {
    knightTour();
    return 0;
}
