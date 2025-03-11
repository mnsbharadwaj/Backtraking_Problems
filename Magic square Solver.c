/*Construct an N x N magic square, where the sum of each row, column, and diagonal is the same. */

#include <stdio.h>

#define N 3

void generateMagicSquare(int n) {
    int magicSquare[N][N];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            magicSquare[i][j] = 0;

    int i = 0, j = n / 2, num = 1;

    while (num <= n * n) {
        magicSquare[i][j] = num++;

        int newI = (i - 1 + n) % n;
        int newJ = (j + 1) % n;

        if (magicSquare[newI][newJ] != 0)
            i = (i + 1) % n;
        else {
            i = newI;
            j = newJ;
        }
    }

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++)
            printf("%3d ", magicSquare[i][j]);
        printf("\n");
    }
}

int main() {
    int n = 3;
    generateMagicSquare(n);
    return 0;
}
