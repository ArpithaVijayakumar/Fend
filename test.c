#include<stdio.h>
int  main(){
    char *t;
    t = "test1.sh";
    execvp("bash",t);
}