# Simple guardian

## Easy alternative to Fail2ban

Build to be **fast to deploy** *(deploying SG and making your server secure against OpenSSH, VSFTPD and Dovecot attacks takes under 6 seconds when using [Simple Guardian Server](https://github.com/esoadamo/simple-guardian-server))* and **easy to configure** *(uses JSON formatted dictionaries as profiles, no regex-skills needed).*

## Configuration

### Profiles

#### Reserved variables

These variables are recognized and used by the parser itself:

| Variable name |                       Represenataion                        |
| :-----------: | :---------------------------------------------------------: |
|    `USER`     |             the user that was target of attack              |
|     `IP`      |            the IP from where the attack has come            |
|    `TIME`     |             time of attack in format `HH:MM:SS`             |
|     `D:M`     |           month of attack - eg. `Jan`, `Feb`,...            |
|     `D:D`     | the day of month the attack has occurred - from `1` to `31` |

### simple-guardian-client

recognized commands:

|    command     |                            action                            | must be runned as root |
| :------------: | :----------------------------------------------------------: | :--------------------: |
|      help      |                         prints help                          |           n            |
|   -V/version   |         print current version of the simple guardian         |           n            |
| login loginKey | logs in with user using loginKey and assigns this instance to the online account and server |           Y            |
|   uninstall    |        completely wipes simple guardian from the disc        |           Y            |
|     update     |    updates s-g to the latest version from GitHub releases    |           Y            |
| update-master  | updates s-g to the latest version from GitHub master branch  |           Y            |
|    unblock     |                  unblocks IP blocked by s-g                  |           Y            |



## Looking for legacy version?

Right now, you can check the legacy version [here](https://github.com/esoadamo/simple-guardian-legacy/) 