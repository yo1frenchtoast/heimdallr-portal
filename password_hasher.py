#!/usr/bin/python
import sys
import hashlib, uuid

password = str(sys.argv[1])
salt = uuid.uuid4().hex
hashed_password = hashlib.sha256(salt + password).hexdigest()
print "Hashed password + salt : {}:{}".format(hashed_password, salt)
