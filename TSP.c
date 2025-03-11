#include <stdio.h>
#include <limits.h>
#include <stdbool.h>

#define N 4
#define INF 99999

int tsp(int graph[N][N], int visited, int pos, int memo[N][1 << N]) {
    if (visited == (1 << N) - 1)  // All cities visited
        return graph[pos][0];

    if (memo[pos][visited] != -1)
        return memo[pos][visited];

    int minCost = INF;

    for (int city = 0; city < N; city++) {
        if (!(visited & (1 << city))) {  // If not visited
            int cost = graph[pos][city] + tsp(graph, visited | (1 << city), city, memo);
            if (cost < minCost)
                minCost = cost;
        }
    }

    return memo[pos][visited] = minCost;
}

int findShortestPath(int graph[N][N]) {
    int memo[N][1 << N];
    for (int i = 0; i < N; i++)
        for (int j = 0; j < (1 << N); j++)
            memo[i][j] = -1;

    return tsp(graph, 1, 0, memo);
}

int main() {
    int graph[N][N] = {
        {0, 10, 15, 20},
        {10, 0, 35, 25},
        {15, 35, 0, 30},
        {20, 25, 30, 0}
    };
    printf("Shortest TSP Path Cost: %d\n", findShortestPath(graph));
    return 0;
}
