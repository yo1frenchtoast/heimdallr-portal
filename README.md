# HEIMDALLR : self-hosted whitelist portal for RouterOS
Use a login page to allow your ip address to connect to your infrastucture

## TODO
* add "create account" page with email validation to admin

## Getting started

### Preriquiries
* mikrotik router with configured ssh access
* python with pip installed (prefered)
* ssl certificate and key files
* systemd based system (if you want to run it as service)

### Installation
Install paramiko and config Python library
```
pip install paramiko
pip install config
```
Clone repo
```
git clone
cp -r heimdallr-portal/ /opt/
```
Add execution rights
``` 
chmod a+x /opt/heimdallr-portal/heimdallr-portal.py
```
Configure settings
```
mkdir /etc/heimdallr-portal/
cp -r heimdallr-portal/etc/heimdallr-portal/ /etc/heimdallr-portal/
vi /etc/heimdallr-portal/config.py

#!/usr/bin/python

###
# These variables are used as settings
HOSTNAME:   "heimdallr.domain.tld"   # ip address of the heimdallr portal web server (public address needed if it runs on public network)
PORT:       9090                  # port in which the heimdallr portal web server listens
REPLY_PORT: 9090                  # port on which the reply will be done (usefull in case of reverse proxifying)
KEY_SSL:    "/etc/letsencrypt/live/heimdallr.domain.tld/privkey.pem"    # path to ssl key to provide client to server security
CERT_SSL:   "/etc/letsencrypt/live/heimdallr.domain.tld/fullchain.pem"  # path to ssl certificate
#
# max attempts on wrong login or password
MAX_RETRY:  3
#
# list of mikrotik routers address ip which will be configured
MK_ROUTER:  [ "10.0.0.254", "192.168.1.1", "123.123.123.123" ]
MK_PORT:    22                          # mikrotik router ssh port to connect
MK_USER:    "admin"                     # mikrotik router user used to connect
MK_SSHKEY:  "/home/admin/.ssh/id_rsa"   # path to the ssh key used to connect to router
MK_EMAIL:   "me@domain.tld"             # email on which router notifications will be send
#
# the usernames and passwords used to log in
# please use provided password-hasher.py to hash your password (usage : python password-hasher.py <yourpassword>)
LOGINS: {
    'test':     '57a5d2a1e1f9ba3a512aea9a77b98d9ab4d3d3189cb3bf9b0081e0db0117f80b:738653896b574287ba55f5db17539502',
}
###
```
Optional : create systemd service
```
cp -r heimdallr-portal/heimdallr-portal.service /lib/systemd/system/
systemctl daemon-reload
systemctl enable heimdallr-portal.service 
service heimdallr-portal start
```
