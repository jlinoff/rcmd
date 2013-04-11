#!/usr/bin/env python
'''
This tool encrypts or decrypts a login configuration file for use in
rcmd.

It is exactly the same as running openssl except that you don't need
to have openssl installed.

    $ # Encrypt
    $ openssl enc -e -a -aes-256-cbc -salt -pass 'pass:password' \\
        -in plaintext -out ciphertext

    $ # Decrypt
    $ openssl enc -d -a -aes-256-cbc -salt -pass 'pass:password' \\
        -in ciphertext -out plaintext

Here is an example of how to use it:

    $ cat >rcmd.dat <<EOF
    # login credentials for rcmd
    {
      "global" : ["admin", "password", 22],
      "host" : {
          "host1" : ["admin", "password", 22],
          "host2" : ["admin", "password", 22],
          "filer1" : ["admin", "password", 22],
          "filer2" : ["admin", "password", 22],
          "ldap1" : ["admin", "password", 22],
          "ldap2" : ["admin", "password", 22],
      }
    }
    EOF
    $ rcmd_crypt.py -e -i plaintext -o cihpertext -p secret
    $ rcmd_crypt.py -d -i cihpertext -o plaintext -p secret

You could also use pipes:

    $ # Encrypt and decrypt some simple text.
    $ echo 'Lorem ipsum dolor sit amet' | \\
        rcmd_crypt.py -e -p secret | \\
        rcmd_crypt.py -d -p secret

This module can also be used as a library:

    #!/usr/bin/env python
    from rcmd_crypt import encrypt, decrypt
    password = 'secret'
    plaintext = 'Lorem ipsum dolor sit amet'
    ciphertext = encrypt(password, plaintext)
    testtext = decrypt(password, ciphertext)
    assert plaintext == testtext
'''
import argparse
import base64
import os
import re
import sys

from getpass import getpass
from pprint import pprint
from Crypto.Cipher import AES


# ================================================================
# _get_key_and_iv
# ================================================================
def _get_key_and_iv(password, salt, klen=32, ilen=16, msgdgst='md5'):
    '''
    Derive the key and the IV from the given password and salt.

    This is a niftier implementation than my direct transliteration of
    the C++ code although I modified to support different digests.

    CITATION: http://stackoverflow.com/questions/13907841
              /implement-openssl-aes-encryption-in-python

    @param password  The password to use as the seed.
    @param salt      The salt.
    @param klen      The key length.
    @param ilen      The initialization vector length.
    @param msgdgst   The message digest algorithm to use.
    '''
    # equivalent to:
    #   from hashlib import <mdi> as mdf
    #   from hashlib import md5 as mdf
    #   from hashlib import sha512 as mdf
    mdf = getattr(__import__('hashlib', fromlist=[msgdgst]), msgdgst)
    passwd = password.encode('ascii', 'ignore')  # convert to ASCII

    try:
        maxlen = klen + ilen
        keyiv = mdf(passwd + salt).digest()
        tmp = [keyiv]
        while len(tmp) < maxlen:
            tmp.append(mdf(tmp[-1] + passwd + salt).digest())
            keyiv += tmp[-1]  # append the last byte
            key = keyiv[:klen]
            ivec = keyiv[klen:klen+ilen]
        return key, ivec
    except UnicodeDecodeError:
        return None, None


# ================================================================
# encrypt
# ================================================================
def encrypt(password, plaintext, chunkit=True, msgdgst='md5'):
    '''
    Encrypt the plaintext using the password using an openssl
    compatible encryption algorithm. It is the same as creating a file
    with plaintext contents and running openssl like this:

    $ cat plaintext
    <plaintext>
    $ openssl enc -e -aes-256-cbc -base64 -salt \\
        -pass pass:<password> -n plaintext

    @param password  The password.
    @param plaintext The plaintext to encrypt.
    @param chunkit   Flag that tells encrypt to split the ciphertext
                     into 64 character (MIME encoded) lines.
                     This does not affect the decrypt operation.
    @param msgdgst   The message digest algorithm.
    '''
    salt = os.urandom(8)
    key, ivec = _get_key_and_iv(password, salt, msgdgst=msgdgst)
    if key is None:
        return None

    # PKCS#7 padding
    padding_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + (chr(padding_len) * padding_len)

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, ivec)
    ciphertext = cipher.encrypt(padded_plaintext)

    # Make openssl compatible.
    # I first discovered this when I wrote the C++ Cipher class.
    # CITATION: http://projects.joelinoff.com/cipher-1.1/doxydocs/html/
    openssl_ciphertext = 'Salted__' + salt + ciphertext
    b64 = base64.b64encode(openssl_ciphertext)
    if not chunkit:
        return b64

    line_len = 64
    chunk = lambda s: '\n'.join(s[i:min(i+line_len, len(s))]
                                for i in xrange(0, len(s), line_len))
    return chunk(b64)


# ================================================================
# decrypt
# ================================================================
def decrypt(password, ciphertext, msgdgst='md5'):
    '''
    Decrypt the ciphertext using the password using an openssl
    compatible decryption algorithm. It is the same as creating a file
    with ciphertext contents and running openssl like this:

    $ cat ciphertext
    # ENCRYPTED
    <ciphertext>
    $ egrep -v '^#|^$' | \\
        openssl enc -d -aes-256-cbc -base64 -salt \\
           -pass pass:<password> -in ciphertext
    @param password   The password.
    @param ciphertext The ciphertext to decrypt.
    @param msgdgst    The message digest algorithm.
    @returns the decrypted data.
    '''

    # unfilter -- ignore blank lines and comments
    filtered = ''
    for line in ciphertext.split('\n'):
        line = line.strip()
        if re.search('^\s*$', line) or re.search('^\s*#', line):
            continue
        filtered += line + '\n'

    # Base64 decode
    raw = base64.b64decode(filtered)
    assert raw[:8] == 'Salted__'
    salt = raw[8:16]  # get the salt

    # Now create the key and iv.
    key, ivec = _get_key_and_iv(password, salt, msgdgst=msgdgst)
    if key is None:
        return None

    # The original ciphertext
    ciphertext = raw[16:]

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, ivec)
    padded_plaintext = cipher.decrypt(ciphertext)

    padding_len = ord(padded_plaintext[-1])
    plaintext = padded_plaintext[:-padding_len]
    return plaintext


# ================================================================
# get_opts
# ================================================================
def _get_opts():
    '''
    Define and parse the command line options.

    Use the pydoc command to get the module documentation and
    incorporate it into the help.

    @returns The options.
    '''
    # Tricky way to get the package description into the help.
    description = 'description:%s' % ('\n  '.join(__doc__.split('\n')))
    epilog = '''
 
copyright:
  Copyright (C) 2013  Joe Linoff
  
  This program is free software: you can redistribute it and/or
  modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
 
  
author:
  Joe Linoff
'''
    rawd = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=rawd,
                                     description=description,
                                     epilog=epilog)
    group1 = parser.add_mutually_exclusive_group(required=False)

    group1.add_argument('-d', '--decrypt',
                        action='store_false',
                        dest='encrypt',
                        help='decrypt the input data')
    group1.add_argument('-e', '--encrypt',
                        action='store_true',
                        dest='encrypt',
                        help='encrypt the input data')
    parser.add_argument('-i', '--input',
                        action='store',
                        metavar=('FILE'),
                        help='input file, default stdin')
    parser.add_argument('-o', '--output',
                        action='store',
                        metavar=('FILE'),
                        help='output file, default stdout')
    parser.add_argument('-p', '--password',
                        action='store',
                        help='the password')
    parser.add_argument('-v', '--verbose',
                        action='count',
                        help='the level of verbosity')
    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s 1.0')

    args = parser.parse_args()

    if args.verbose:
        print '''
%s  Copyright(C) 2013  Joe Linoff
This program comes with ABSOLUTELY NO WARRANTY; for details type visit
http://www.gnu.org/licenses/.
This is free software, and you are welcome to redistribute it under
certain conditions; see the above web site for details.
''' % os.path.basename(__file__)

    if args.verbose > 2:
        pprint(args, indent=4)

    return args


# ================================================================
# main
# ================================================================
def _main():
    '''
    Run the program.
    '''
    opts = _get_opts()

    password = opts.password
    if password is None:
        password = getpass('Password: ')

    if opts.input:
        try:
            ifp = open(opts.input, 'r')
            input_data = ifp.read()
            ifp.close()
        except IOError as exp:
            print 'ERROR: input file open failed "%s" (%s).' % (opts.input,
                                                                str(exp))
            sys.exit(1)
    else:
        input_data = sys.stdin.read()

    if opts.encrypt:
        output_data = encrypt(password, input_data)
    else:
        try:
            output_data = decrypt(password, input_data)
        except AssertionError as exp:
            print 'ERROR: decryption failed, bad password? (%s)' % (str(exp))
            sys.exit(1)

    if opts.output:
        try:
            ofp = open(opts.output, 'w')
            ofp.write(output_data)
            ofp.close()
        except IOError as exp:
            print 'ERROR: output file open failed "%s" (%s).' % (opts.input,
                                                                 str(exp))
            sys.exit(1)
    else:
        sys.stdout.write('%s' % (output_data))
        sys.stdout.flush()


# ================================================================
# MAIN
# ================================================================
if __name__ == '__main__':
    _main()
