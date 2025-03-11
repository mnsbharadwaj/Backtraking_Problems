/*Find a cycle that visits every node exactly once and returns to the start.*/
#include <stdio.h>
#include <stdbool.h>

#define V 5

bool isSafe(int v, int graph[V][V], int path[], int pos) {
    if (graph[path[pos - 1]][v] == 0) return false;  // No edge
    for (int i = 0; i < pos; i++)
        if (path[i] == v) return false;  // Already visited
    return true;
}

bool solveHamiltonian(int graph[V][V], int path[], int pos) {
    if (pos == V)  // All vertices visited
        return graph[path[pos - 1]][path[0]] == 1;  // Check cycle

    for (int v = 1; v < V; v++) {
        if (isSafe(v, graph, path, pos)) {
            path[pos] = v;
            if (solveHamiltonian(graph, path, pos + 1))
                return true;
            path[pos] = -1;  // Backtrack
        }
    }
    return false;
}

void findHamiltonianCycle(int graph[V][V]) {
    int path[V];
    for (int i = 0; i < V; i++) path[i] = -1;

    path[0] = 0;  // Start from vertex 0
    if (solveHamiltonian(graph, path, 1)) {
        for (int i = 0; i < V; i++)
            printf("%d -> ", path[i]);
        printf("0\n");
    } else {
        printf("No Hamiltonian Cycle exists\n");
    }
}

int main() {
    int graph[V][V] = {
        {0, 1, 0, 1, 0},
        {1, 0, 1, 1, 1},
        {0, 1, 0, 0, 1},
        {1, 1, 0, 0, 1},
        {0, 1, 1, 1, 0}
    };
    findHamiltonianCycle(graph);
    return 0;
}
