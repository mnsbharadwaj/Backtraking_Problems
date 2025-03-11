#include <stdio.h>

#define N 4

int moves[4][2] = {{1, 0}, {0, 1}, {-1, 0}, {0, -1}};  // Down, Right, Up, Left

void printSolution(int sol[N][N]) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++)
            printf("%d ", sol[i][j]);
        printf("\n");
    }
}

int isSafe(int maze[N][N], int x, int y) {
    return (x >= 0 && x < N && y >= 0 && y < N && maze[x][y] == 1);
}

int solveMazeRec(int maze[N][N], int x, int y, int sol[N][N]) {
    if (x == N - 1 && y == N - 1) {  // Reached destination
        sol[x][y] = 1;
        return 1;
    }

    if (isSafe(maze, x, y)) {
        sol[x][y] = 1;

        for (int i = 0; i < 4; i++) {
            int nextX = x + moves[i][0];
            int nextY = y + moves[i][1];

            if (solveMazeRec(maze, nextX, nextY, sol))
                return 1;
        }

        sol[x][y] = 0;  // Backtrack
    }

    return 0;
}

void solveMaze(int maze[N][N]) {
    int sol[N][N] = {0};

    if (solveMazeRec(maze, 0, 0, sol))
        printSolution(sol);
    else
        printf("No solution exists\n");
}

int main() {
    int maze[N][N] = {
        {1, 0, 0, 0},
        {1, 1, 0, 1},
        {0, 1, 0, 0},
        {1, 1, 1, 1}
    };

    solveMaze(maze);
    return 0;
}
