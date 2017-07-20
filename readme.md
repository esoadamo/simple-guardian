# Simple guardian
## Easy alternative to fail2ban
Last week I was too lazy to learn how to make working Fail2Ban filters, It appears too hard. So I decided to do something easier and more lightweight.
## Installation
### New
```bash
git clone https://github.com/esoadamo/simple-guardian.git
cd simple-guardian
sudo ./install.sh
```
Configuration file is located on `/etc/simple-guardian/guardian.conf`
Run it with `simple-guarian --help` 
### Update
`sudo ./install.sh update` - updates only script, leaves all config unmodified
### Automatic scan
`sudo ./install.sh crontab` - schedules scanning every 10 minutes + sending logs every day at 18:00


## Configuration
Configuration file is located on `/etc/simple-guardian/guardian.conf`
Configuration file has two parts
### `--GLOBAL-CONFIG--` 
Here are stored all variables that are same for every profile

 - `MaxAttempts` - how many attempts before IP gets blocked
 - `BlockCommand` - command that gets executed to block IP. %IP% is replaced with blocked IP
 - `SendMail` - mail address to which the log will be sent, if omitted then no email is ever send
 - `MailCommand` - command that gets executed to send email, uses parameters *%SUBJECT%*, *%MESSAGE%* and *%TARGET_MAIL%*, if omitted then no email is ever send
 - `SaveBlocked` - if not omitted, then here is saved list of blocked IPs, one per line
### `--PROFILES--` 
By default configuration has in-build profiles for OpenSSH server, dovecot and vsftpd
Every profile stars with its name `[ProfileName]`
Every profile should have defined it's log file with `LogFile=`
Then you have to specify filters
#### Filters
filters starts with `>>`
they are lines from log file, but all variables are replaced with `%VariableName%`
right now script recognizes this variables:
 - `%USER%` - username that was target of attack
 - `%IP%` - attacking IP
 - `%D:M% ` - month in format Jan, Feb, ..., Dec
 - `%D:D%` - day in month ( from 01 to 31 )
 - `%TIME%` - time in format hours:minutes:seconds
# Have own filters and profiles?
Great! Do not hesitate and send them to me! I will be glad to implement them.
