# Simple guardian

## Easy alternative to Fail2ban

Build to be **fast to deploy** *(deploying SG and making your server secure against OpenSSH, VSFTPD and Dovecot attacks takes under 6 seconds when using [Simple Guardian Server](https://github.com/esoadamo/simple-guardian-server))* and **easy to configure** *(uses JSON formatted dictionaries as profiles, no regex-skills needed).*

[TOC]

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



## Looking for legacy version?

Right now, you can check the legacy version [here](https://github.com/esoadamo/simple-guardian-legacy/) 