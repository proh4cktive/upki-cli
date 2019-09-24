#!/bin/bash

function is_url {
    regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
    if [[ $1 =~ $regex ]]; then
        return 0
    fi
    return 1
}

# If user is not root, try sudo
if [[ $EUID -ne 0 ]]; then
    sudo -p
fi

# Setup vars
USERNAME=${USER}
GROUPNAME=$(id -gn $USER)
INSTALL=${PWD}

usage="$(basename "$0") [-h] [-u https://certificates.domain.com] -- Install script for uPKI client auto renewal service

where:
    -h  show this help text
    -u  set the RA listening url
"

UPKI_URL=''

while getopts ':hu:' option; do
  case "$option" in
    h) echo "$usage"
       exit
       ;;
    u) UPKI_URL=$OPTARG
       ;;
    :) printf "missing argument for -%s\n" "$OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
   \?) printf "illegal option: -%s\n" "$OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
  esac
done
shift $((OPTIND - 1))

# Request CA listening ip from user if needed
if [[ -z "$UPKI_URL" ]]; then
    read -p "Enter RA url: " UPKI_URL
    while ! is_url "$UPKI_URL"
    do
        read -p "Not a valid URL. Re-enter: " UPKI_URL
    done
fi

# Install required libs
pip3 install -r requirements.txt

# Create cli service
sudo tee /etc/systemd/system/upki-cli.service > /dev/null <<EOT
[Unit]
Description=µPki Client Renewal service
ConditionACPower=true
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USERNAME}
Group=${GROUPNAME}
Restart=always
ExecStart=${INSTALL}/client.py --url ${UPKI_URL} renew

[Install]
WantedBy=upki-cli.timer
EOT

# Create Client certificate renewal service timer (every days @ 2:AM)
sudo tee /etc/systemd/system/upki-cli.timer > /dev/null <<EOT
[Unit]
Description=µPki Client certificate renewal service timer

[Timer]
OnBootSec=1min
OnCalendar= *-*-* 02:00:00
RandomizedDelaySec=1hour
Unit=upki-cli.service
Persistent=true

[Install]
WantedBy=timers.target
EOT

# Activate services & timers
sudo systemctl daemon-reload
sudo systemctl enable upki-cli.timer