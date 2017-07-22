#!/bin/bash
INSTALLATION_DIRECTORY="/etc/simple-guardian"
EXEC_PATH="/usr/bin/simple-guarian"

function check {
    if [ $? -ne 0 ]; then
        echo $1
        exit 1
    fi
}

if [ "$1" == "crontab" ]; then
    echo "Installing crontab"
    
    read -p "Do you really want schedule scanning with user $(whoami)? (y/N): "
    if [ "$REPLY" != "y" ]; then
        echo "Ok, bye"
        exit 
    fi
    
    crontab -l > crontab-file
    
    echo "" >> crontab-file
    echo "# Simple guardian: Scan every 10 minutes and send info every 24 hours at 18:00" >> crontab-file
    echo "*/10 * * * * $EXEC_PATH 600 --no-email > /dev/null" >> crontab-file
    echo "00 18 * * * $EXEC_PATH 86400 > /dev/null" >> crontab-file
    
    crontab crontab-file
    
    rm crontab-file
    
    echo "Scheduled scanning every 10 minutes and sending info mails every 24 hours at 18:00"
    
    exit 0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $SCRIPT_DIR

if [ "$1" == "update" ]; then
    echo "Updating script"
    
    cp simple-guardian.py $INSTALLATION_DIRECTORY/simple-guardian.py
    check "Copying new version of script failed"
    
    exit 0
fi

echo "Installing simple guardian to directory $INSTALLATION_DIRECTORY"

mkdir $INSTALLATION_DIRECTORY
check "Creating installation directory failed ($INSTALLATION_DIRECTORY)"

cp * $INSTALLATION_DIRECTORY
check "Copying files to installation directory failed"

echo "#!/bin/bash
python3 $INSTALLATION_DIRECTORY/simple-guardian.py \"\$@\"" > $EXEC_PATH
check "Creating executable file ($EXEC_PATH) failed"

chmod +x $EXEC_PATH
check "Making $EXEC_PATH executable failed"

echo "Installation complete."
echo "Edit configuration file on $INSTALLATION_DIRECTORY/guardian.conf"
echo "Run with 'simple-guardian --help'"

