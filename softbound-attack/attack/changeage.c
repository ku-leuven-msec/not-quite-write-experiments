#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_USERS 5


volatile int* adminLevel = 0;
struct user {
    int age;
}* users[NUM_USERS];

int main() {
    // initialize 
    for (int i = 0;  i < NUM_USERS; i++) {
        users[i] = malloc(sizeof(struct user));
        users[i]->age = i*2;
    }
    adminLevel = malloc(sizeof(int));
    *adminLevel = 0;

    // ask user to update their age
    int userID;
    printf("What is your user ID? ");
    scanf("%d", &userID);
    int age;
    printf("What is your updated age? ");
    scanf("%d", &age);

    // the exploitable read
    struct user* user = users[userID];
    // the hardened write
    user->age = age;

    if (*adminLevel > 2) {
        printf("Launching shell for admin: \n");
        system("/bin/bash");
    }
}
