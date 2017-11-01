#!/usr/bin/python
#
# Python script to generate a hash for /etc/shadow (SHA512) and LDAP (SSHA1) 
# In case you needed to support a hypothetical environment that had both auth mechanisms in play.
#

import hashlib
from base64 import urlsafe_b64encode as encode
from base64 import urlsafe_b64decode as decode
from getpass import getpass
import crypt
import os

def hashssha1(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + encode(h.digest() + salt)

def hash512(password):
    h = crypt.crypt(password, "$6$LRyk3moKj9ddiVTY")
    return(h)

if __name__ == '__main__':
    passin = getpass('Please enter clear-text password: ')
#    print("cats " + passin)
    print("SSHA1  :: " + hashssha1(passin))
    print("SHA512 :: " + hash512(passin))