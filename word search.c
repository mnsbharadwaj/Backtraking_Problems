#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define ROWS 3
#define COLS 4

int directions[4][2] = {{0,1}, {1,0}, {0,-1}, {-1,0}};  // Right, Down, Left, Up

bool backtrack(char board[ROWS][COLS], int r, int c, char *word, int index, int visited[ROWS][COLS]) {
    if (word[index] == '\0') return true;  // Found word
    if (r < 0 || c < 0 || r >= ROWS || c >= COLS || visited[r][c] || board[r][c] != word[index])
        return false;  

    visited[r][c] = 1;  // Mark as visited

    for (int d = 0; d < 4; d++) {
        int nr = r + directions[d][0], nc = c + directions[d][1];
        if (backtrack(board, nr, nc, word, index + 1, visited))
            return true;
    }

    visited[r][c] = 0;  // Backtrack
    return false;
}

bool exist(char board[ROWS][COLS], char *word) {
    int visited[ROWS][COLS] = {0};

    for (int i = 0; i < ROWS; i++)
        for (int j = 0; j < COLS; j++)
            if (board[i][j] == word[0] && backtrack(board, i, j, word, 0, visited))
                return true;

    return false;
}

int main() {
    char board[ROWS][COLS] = {
        {'A','B','C','E'},
        {'S','F','C','S'},
        {'A','D','E','E'}
    };
    
    printf("Exists: %s\n", exist(board, "ABCCED") ? "YES" : "NO");
    return 0;
}
