/*Given a dictionary of words and a string, check if the string can be segmented into words from the dictionary.*/
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define DICT_SIZE 5

const char* dictionary[DICT_SIZE] = {"apple", "pen", "applepen", "pine", "pineapple"};

bool isWordInDict(const char *word) {
    for (int i = 0; i < DICT_SIZE; i++)
        if (strcmp(word, dictionary[i]) == 0)
            return true;
    return false;
}

void wordBreakUtil(char *str, int start, char *result) {
    int len = strlen(str);
    
    if (start == len) {
        printf("%s\n", result);
        return;
    }

    char temp[100];
    strcpy(temp, result);

    for (int i = start; i < len; i++) {
        char word[20] = "";
        strncpy(word, str + start, i - start + 1);
        word[i - start + 1] = '\0';

        if (isWordInDict(word)) {
            strcat(temp, word);
            strcat(temp, " ");
            wordBreakUtil(str, i + 1, temp);
            temp[strlen(temp) - (strlen(word) + 1)] = '\0';  // Backtrack
        }
    }
}

void wordBreak(char *str) {
    char result[100] = "";
    wordBreakUtil(str, 0, result);
}

int main() {
    char str[] = "pineapplepenapple";
    wordBreak(str);
    return 0;
}
