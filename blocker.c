#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#define iptables /sbin/iptables
#define username "simpleguardian"
#define indexCommand 1  
#define indexIp 2

void help(int exitStatus){
    printf("usage: blocker block/unblock ip\n");
    exit(exitStatus);
}

int check_user_valid(){
    uid_t uid;
    struct passwd *udetails;

    uid = getuid();
    udetails = getpwuid(uid);

    return !strcmp(username, udetails->pw_name) || !strcmp("root", udetails->pw_name);
}


int main(int argc, char **argv){
    if (!check_user_valid()){
        printf("this program is exclusive for user %s or root\n", username);
        exit(1);
    }
    setuid(0);
    if (argc < indexIp + 1){
        help(0);
    }
    if (!strcmp("block",argv[indexCommand])){
        printf("blocking %s\n", argv[indexIp]);

        char command[] = "iptables -A INPUT -s %s -j DROP";
        char *command_formatted = (char*)malloc(sizeof(command) + sizeof(argv[indexIp]));
        sprintf(command_formatted, command, argv[indexIp]);

        system(command_formatted);

        exit(0);
    } else if (!strcmp("unblock",argv[indexCommand])){
        printf("unblocking %s\n", argv[indexIp]);

        char command[] = "iptables -D INPUT -s %s -j DROP";
        char *command_formatted = (char*)malloc(sizeof(command) + sizeof(argv[indexIp]));
        sprintf(command_formatted, command, argv[indexIp]);

        system(command_formatted);

        exit(0);
    }
    help(1);
}