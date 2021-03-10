#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#define iptables /sbin/iptables
#define ipset /sbin/ipset
#define username "simpleguardian"
#define indexCommand 1
#define indexIp 2

/**
 ____  _            _
| __ )| | ___   ___| | _____ _ __
|  _ \| |/ _ \ / __| |/ / _ \ '__|
| |_) | | (_) | (__|   <  __/ |
|____/|_|\___/ \___|_|\_\___|_|
======================================
Program that uses iptables to block or unblock IP
Usage: first init with ./blocker init
then proceed with blocker block/unblock IP

Is supposed to be executed with root privileges, so as protection from executing by unauthorized user
the program checks if you are user simpleguardian or root.
Before blocking IP the program checks if it is not blocked yet to prevent duplicated entries.

After compiling, it is recommended to run following commands:
chown root:root blocker
chmod 755 blocker
chmod u+s blocker
*/

void help(int exitStatus){
    printf("usage: init with: blocker init\n");
    printf("then usage: blocker block/unblock ip\n");
    exit(exitStatus);
}

void check_requirements() {
    if (system("iptables -h > /dev/null 2>&1") != 0) {
        printf("ERROR: iptables command is missing\n");
        exit(1);
    }
    if (system("ipset -h > /dev/null 2>&1") != 0) {
        printf("ERROR: ipset command is missing\n");
        exit(1);
    }
}

int check_ip_valid(const char *ip) {
    const size_t len = strlen(ip);
    for (size_t i = 0; i < len; i++) {
        const char ch = ip[i];
        if (ch == '.' || ch == ':' || ch == '[' || ch == ']') {
            continue;
        }

        if (('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9')) {
            continue;
        }

        return 0;
    }

    return 1;
}

int check_user_valid(){
    uid_t uid;
    struct passwd *udetails;

    uid = getuid();
    udetails = getpwuid(uid);

    return !strcmp(username, udetails->pw_name) || !strcmp("root", udetails->pw_name);
}

int is_already_blocked(char **argv) {
    /*
    Checks if passed IP is already blocked
    Returns 0 if not blocked, 1 if already blocked
    */
    char command_check_if_blocked[] = "ipset test simpleguardian %s > /dev/null 2>&1";
    char *command_check_if_blocked_formatted = (char*)malloc(50 + sizeof(command_check_if_blocked) + sizeof(argv[indexIp]));
    sprintf(command_check_if_blocked_formatted, command_check_if_blocked, argv[indexIp]);
    return system(command_check_if_blocked_formatted) == 0;
}

int main(int argc, char **argv){
    check_requirements();

    if (!check_user_valid()){
        printf("this program is exclusive for user %s or root\n", username);
        exit(1);
    }
    if (argc < indexCommand + 1){
        help(0);
    }

    setuid(0);

    if (!strcmp("init", argv[indexCommand])){
        if (system("ipset list simpleguardian > /dev/null 2>&1") == 0){
            printf("already inited before, just flushing\n");
            system("ipset flush simpleguardian > /dev/null 2>&1");
            exit(0);
        } else {
            system("ipset create simpleguardian iphash > /dev/null 2>&1");
            printf("init complete\n");
            system("iptables -I INPUT 2 -m set --match-set simpleguardian src -j DROP");
            exit(0);
        }
    }

    if (argc < indexIp + 1){
        help(0);
    }
    if (!strcmp("block", argv[indexCommand])){
        const char *ip = argv[indexIp];

        if (!check_ip_valid(ip)) {
            printf("this IP is invalid (%s)\n", ip);
            exit(1);
        }

        if (is_already_blocked(argv)) {
            printf("this IP is already blocked\n");
            exit(0);
        }

        printf("blocking %s\n", argv[indexIp]);
        char command[] = "ipset add simpleguardian '%s' > /dev/null 2>&1";
        char *command_formatted = (char*)malloc(50 + strlen(command) + strlen(ip));
        sprintf(command_formatted, command, ip);

        system(command_formatted);

        exit(0);
    } else if (!strcmp("unblock", argv[indexCommand])){
        const char *ip = argv[indexIp];

        if (!check_ip_valid(ip)) {
            printf("this IP is invalid (%s)\n", ip);
            exit(1);
        }

        if (!is_already_blocked(argv)) {
            printf("this IP is not blocked\n");
            exit(0);
        }

        printf("unblocking %s\n", argv[indexIp]);

        char command[] = "ipset del simpleguardian '%s' > /dev/null 2>&1";
        char *command_formatted = (char*)malloc(50 + strlen(command) + strlen(ip));
        sprintf(command_formatted, command, ip);

        system(command_formatted);

        exit(0);
    }
    help(1);
}
