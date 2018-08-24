# HEIMDALLR : self-hosted whitelist portal for RouterOS
Use a login page to allow your ip address to connect to your infrastucture

## TODO
* add "create account" page with email validation to admin

## Getting started

### Requirements
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
```
Optional : create systemd service
```
cp -r heimdallr-portal/heimdallr-portal.service /lib/systemd/system/
systemctl daemon-reload
systemctl enable heimdallr-portal.service 
service heimdallr-portal start
```

### Configuration explanations
```
[SERVER]
hostname = heimdallr.domain.tld                                             # ip address of the heimdallr portal web server (public address needed if it runs on public network)
port = 9090                                                                 # port in which the heimdallr portal web server listens
reply_port = 9090                                                           # port on which the reply will be done (usefull in case of reverse proxifying)
ssl_key = /etc/letsencrypt/live/heimdallr.domain.tld/privkey.pem            # path to ssl key to provide client for server security (https)
ssl_cert = /etc/letsencrypt/live/heimdallr.domain.tld/fullchain.pem         # path to ssl certificate

[SECURITY]
max_retry = 3                                                               # max attempts on wrong login or password

[ROUTERS]
list = ["10.0.0.254", "192.168.1.1", "123.123.123.123"]                     # list of mikrotik routers address ip which will be configured
ssh_port = 22                                                               # mikrotik router ssh port to connect
ssh_key = /home/admin/.ssh/id_rsa                                           # path to the ssh key used to connect to router
ssh_user = admin                                                            # mikrotik router user used to connect
admin_email = me@domain.tld                                                 # email on which router notifications will be send

[USERS]
list = {
    'test': '57a5d2a1e1f9ba3a512aea9a77b98d9ab4d3d3189cb3bf9b0081e0db0117f80b:738653896b574287ba55f5db17539502',
}                                                                           # the usernames and passwords used to log in
                                                                            # please use provided password-hasher.py to hash your password (usage : python password-hasher.py <yourpassword>)
```
