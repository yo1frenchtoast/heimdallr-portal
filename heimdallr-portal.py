#!/usr/bin/python
import subprocess
import BaseHTTPServer
import cgi
import paramiko
import re
import ast
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
config.read('config.ini')

server_url = config.get('SERVER', 'url')
server_port = int(config.get('SERVER', 'port'))
server_reply_port = int(config.get('SERVER', 'reply_port'))
server_ssl_key = config.get('SERVER', 'ssl_key')
server_ssl_cert = config.get('SERVER', 'ssl_cert')
server_max_retry = int(config.get('SERVER', 'max_retry'))

router_list = config.get('ROUTER', 'list').split(',')
router_ssh_port = int(config.get('ROUTER', 'ssh_port'))
router_ssh_key = config.get('ROUTER', 'ssh_key')
router_ssh_user = config.get('ROUTER', 'ssh_user')
router_admin_email = config.get('ROUTER', 'admin_email')

user_list = ast.literal_eval(config.get('USER', 'list'))

recaptcha_site_key = config.get('RECAPTCHA', 'site_key')

# scoring for blacklisting
scoring = {}

# functions
def check_password(stored_password, user_password):
    hashed_password, stored_salt = stored_password.split(':')
    return hashed_password == hashlib.sha256(stored_salt + user_password).hexdigest()

def set_firewall(address_list, remote_address):
    firewall = '/ip firewall address-list add list='+ address_list +' timeout=2h comment="added by heimdallr-portal.py" address='+ remote_address +';'
    log = '/log warning "heimdallr-portal.py : added '+ remote_address +' to '+ address_list +' address-list for 2 hours";'
    email = '/tool e-mail send to='+ router_admin_email +' subject="$[/system identity get name] heimdallr-portal.py : added '+ remote_address +' to '+ address_list +' address-list for 2 hours";'
    command = firewall + log + email

    #default message is success
    message = "You are now authorized with address {}".format(remote_address)

    output = {}
    for router in router_list:
	logging.info('Updating address-list on router {}'.format(router))
	client.connect(hostname=router, port=router_ssh_port, username=router_ssh_user, pkey=paramiko_rsa_key)
	stdin,stdout,stderr = client.exec_command(command)
	output = stdout.read().rstrip()
	logging.info('Return for {} : {}'.format(router, output))

	if re.search('failure', output):
	    if re.search('already', output):
	        message = "You are already authorized in list \"{}\" with address {} ({})".format(address_list, remote_address, output)
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
    """%(server_url, server_reply_port)
    #the login page
    html_login = """
    <html>
    <head>
        <style type="text/css">
            .text-xs-center {
                text-align: center;
            }
            .g-recaptcha {
                display: inline-block;
            }
        </style>
        <script src='https://www.google.com/recaptcha/api.js'></script>
    </head>
    <body>
        <div class="text-xs-center">
            <b>LOGIN</b>
            <form method="POST" action="do_login">
                username: <input type="text" name="username" required><br>
                password: <input type="password" name="password" required><br>

                <div class="g-recaptcha" data-sitekey="%s">
                </div>

            <input type="submit" value="Submit">
            </form>
        </div>
    </body>
    </html>
    """%(recaptcha_site_key)

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
        remote_address = self.client_address[0]

        #dummy security check
        if username in user_list and check_password(user_list[username], password):
            #authorized user
            logging.info('New authorization from {} for user {}'.format(remote_address, username))
            message = set_firewall('allowed', remote_address)
            self.wfile.write(message)
        else:
            logging.warning('Wrong login or password from {} for user {}'.format(remote_address, username))

            #increment counter until blacklist
            if remote_address in scoring:
                scoring[remote_address] += 1
            else:
                scoring.update({remote_address: 1})
            logging.warning('Current scoring for {} = {}'.format(remote_address, scoring[remote_address]))

            if scoring[remote_address] > server_max_retry:
                logging.warning('Attempt limit by address exceeded {} for {} : blacklisting'.format(server_max_retry, remote_address))

                set_firewall('blacklisted', remote_address)
                del scoring[remote_address]

            #show the login form
            self.wfile.write(self.html_login)

    #the following function makes server produce no output
    #comment it out if you want to print diagnostic messages
    #def log_message(self, format, *args):
    #    return

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%d-%d %H:%M:%S', level=logging.INFO)

    logging.info('Starting web server on {}:{}'.format(server_url, server_port))
    httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', server_port), CaptivePortal)

    logging.info('Activating ssl')
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=server_ssl_key, certfile=server_ssl_cert, server_side=True)

    logging.info('Initializing connection to router '+ ', '.join(router_list))
    paramiko_rsa_key = paramiko.RSAKey.from_private_key_file(router_ssh_key)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    logging.info('Ready')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    client.close()
