#!/usr/bin/python
import subprocess
import BaseHTTPServer
import cgi
import paramiko
import re
import ssl
import hashlib
import logging
import configparser

###
## HEIMDALLR : RouterOS whitelisting portal
## - ytanguy, 2017-12-06
##
## inspired by https://github.com/nikosft/login-portal
###

# import configuration
config = configparser.ConfigParser()
config.read('/etc/heimdallr-portal/config.ini')

# scoring for blacklisting
scoring = {}

# functions
def check_password(stored_password, user_password):
    hashed_password, stored_salt = stored_password.split(':')
    return hashed_password == hashlib.sha256(stored_salt + user_password).hexdigest()

def set_firewall(list, remote_IP):
    firewall = '/ip firewall address-list add list='+ list +' timeout=2h comment="added by heimdallr-portal.py" address='+ remote_IP +';'
    log = '/log warning "heimdallr-portal.py : added '+ remote_IP +' to '+ list +' address-list for 2 hours";'
    email = '/tool e-mail send to='+ config['ROUTERS']['admin_email'] +' subject="$[/system identity get name] heimdallr-portal.py : added '+ remote_IP +' to '+ list +' address-list for 2 hours";'
    command = firewall + log + email

    #default message is success
    message = "You are now authorized with address {}".format(remote_IP)

    output = {}
    for router in config['ROUTERS']['list']:
	logging.info('Updating address-list on router {}'.format(router))
	client.connect(hostname=router, port=int(config['ROUTERS']['ssh_port']), username=config['ROUTERS']['ssh_user'], pkey=KEY)
	stdin,stdout,stderr = client.exec_command(command)
	output = stdout.read().rstrip()
	logging.info('Return for {} : {}'.format(router, output))

	if re.search('failure', output):
	    if re.search('already', output):
	        message = "You are already authorized in list \"{}\" with address {} ({})".format(list, remote_IP, output)
	    else:
		message = "Error while processing request ({})".format(output)

    return message

'''
http server used by the the login portal
'''
class CaptivePortal(BaseHTTPServer.BaseHTTPRequestHandler):
    #this is the index of the login portal
    #it simply redirects the user to the to login page
    html_redirect = """
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url=https://%s:%s/login" />
    </head>
    <body>
        <b>Redirecting to login page</b>
    </body>
    </html>
    """%(config['SERVER']['hostname'], config['SERVER']['reply_port'])
    #the login page
    html_login = """
    <html>
    <head>
        <style type="text/css">
            .center-div {
                margin:50px auto;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="center-div">
            <b>LOGIN</b>
            <form method="POST" action="do_login">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Submit">
            </form>
        </div>
    </body>
    </html>
    """

    '''
    if the user requests the login page show it, else
    use the redirect page
    '''
    def do_GET(self):
        path = self.path
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if path == "/login":
            self.wfile.write(self.html_login)
        else:
            self.wfile.write(self.html_redirect)

    '''
    this is called when the user submits the login form
    '''
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        username = form.getvalue("username")
        password = form.getvalue("password")
        remote_IP = self.client_address[0]

        #dummy security check
        if username in config['USERS']['list'] and check_password(config['USERS']['list'][username], password):
            #authorized user
            logging.info('New authorization from {} for user {}'.format(remote_IP, username))
            message = set_firewall('allowed', remote_IP)
            self.wfile.write(message)
        else:
            logging.warning('Wrong login or password from {} for user {}'.format(remote_IP, username))

            #increment counter until blacklist
            if remote_IP in scoring:
                scoring[remote_IP] += 1
            else:
                scoring.update({remote_IP: 1})
            logging.warning('Current scoring for {} = {}'.format(remote_IP, scoring[remote_IP]))

            if scoring[remote_IP] > config['SECURITY']['max_retry']:
                logging.warning('Attempt limit by address exceeded {} for {} : blacklisting'.format(config['SECURITY']['max_retry'], remote_IP))

                set_firewall('blacklisted', remote_IP)
                del scoring[remote_IP]

            #show the login form
            self.wfile.write(self.html_login)

    #the following function makes server produce no output
    #comment it out if you want to print diagnostic messages
    #def log_message(self, format, *args):
    #    return

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%d-%d %H:%M:%S', level=logging.INFO)

    logging.info('Starting web server on {}:{}'.format(config['SERVER']['hostname'], config['SERVER']['port']))
    httpd = BaseHTTPServer.HTTPServer(('', int(config['SERVER']['Port'])), CaptivePortal)

    logging.info('Activating ssl')
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=config['SERVER']['ssl_key'], certfile=config['SERVER']['ssl_cert'], server_side=True)

    logging.info('Initializing connection to router '+ ';'.join(config['ROUTERS']['list']))
    KEY = paramiko.RSAKey.from_private_key_file(config['ROUTERS']['ssh_key'])
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    logging.info('Ready')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    client.close()
