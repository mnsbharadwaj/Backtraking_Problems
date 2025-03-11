#include <stdio.h>
#include <stdbool.h>

#define N 4  // Change this for larger boards

bool isSafe(int board[N][N], int row, int col) {
    for (int i = 0; i < row; i++)  // Check column
        if (board[i][col]) return false;

    for (int i = row, j = col; i >= 0 && j >= 0; i--, j--)  // Check left diagonal
        if (board[i][j]) return false;

    for (int i = row, j = col; i >= 0 && j < N; i--, j++)  // Check right diagonal
        if (board[i][j]) return false;

    return true;
}

bool solveNQueens(int board[N][N], int row) {
    if (row >= N) {  // Solution found
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < N; j++)
                printf(board[i][j] ? "Q " : ". ");
            printf("\n");
        }
        printf("\n");
        return true;
    }

    for (int col = 0; col < N; col++) {
        if (isSafe(board, row, col)) {
            board[row][col] = 1;  // Place queen
            solveNQueens(board, row + 1);
            board[row][col] = 0;  // Backtrack
        }
    }
    return false;
}

int main() {
    int board[N][N] = {0};
    solveNQueens(board, 0);
    return 0;
}
