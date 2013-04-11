#!/usr/bin/env python
r'''
This tool runs remote commands on one or more hosts using the SSH
protocol.

It is a very flexible tool that can be used to automate all sorts of
different administration tasks especially when it is tied into an
encrypted login configuration file.

Rather than try to describe all of the options here, I am going to
present a couple of examples and refer you to the HELP.txt and files
in the examples subdirectory that are provided with the package.

Here the first example. It shows the simplest use of the tool to run a
command on a couple of hosts using the same login for all of them.

  $ # Display the host names.
  $ rcmd.py -u root -H host1,host2 -c hostname
  root password:
  host1
  host2

This is not a very realistic example because it requires specifying
the username, the password, the hosts and the commands manually. For
systems with more than a small number of hosts, this is unwieldy.

Instead, you would typically define a configuration file that
describes the hosts with login information and a batch file that
executes multiple commands. This is shown in the realistic example
below:

  $ # Check the disks on the physical servers.
  $ ./disk-check.sh
  login.conf password:

  DISK HEALTH REPORT Sat Mar 30 10:02:37 PDT 2013

    Hostname  O/S   Device              Capacity Type                    Health
    ========= ===== =================== ======== ======================= ======
    server-01 Linux /dev/sda            250 GB   WDC WD2502ABYS-18B7A0   PASSED
    server-01 Linux /dev/sdb            250 GB   WDC WD2502ABYS-18B7A0   PASSED
    server-01 Linux /dev/sdc            250 GB   WDC WD2502ABYS-18B7A0   PASSED
    server-01 Linux /dev/sdd            250 GB   WDC WD2502ABYS-18B7A0   PASSED
    server-02 Linux /dev/sda            250 GB   WDC WD2502ABYS-18B7A0   PASSED
    server-02 Linux /dev/sdb            250 GB   WDC WD2502ABYS-18B7A0   PASSED
    .
    .
    server-42 SunOS /dev/rdsk/c3t11d0s0 2.00 TB  Hitachi HUA722020ALA330 PASSED
    server-42 SunOS /dev/rdsk/c3t12d0s0 2.00 TB  Hitachi HUA722020ALA330 PASSED
    server-42 SunOS /dev/rdsk/c3t13d0s0 2.00 TB  Hitachi HUA722020ALA330 PASSED
    <output snipped>

This is what the shell script looks like:

  $ cat disk-check.sh
  #!/bin/bash
  cat <<EOF

    DISK HEALTH REPORT `date`

      Hostname  O/S   Device              Capacity Type                    Health
      ========= ===== =================== ======== ======================= ======
  EOF
  rcmd.py -L login.conf 'secret' -H '^server-\d+$' -b disk-check-sub.sh
  echo

As you can see it is very simple. The configuration information is
stored in the login.conf file, the password is 'secret', the hosts are
all hosts in the conf file that match the '^server-\d+$' regular
expression and the batch file is disk-check-sub.sh.

The login.conf file can be stored encrypted or in plaintext. If you
store it in encrypted format, a password will be required when it is
used. A password is not required if it is plaintext.

I always store it in encrypted format. This is what the encrypted
login.conf file looks like:

  $ cat login.conf
  U2FsdGVkX1+Se7D9+63rMhibkc1nMtE6J6V6QV2AfuqoABboatRFaE78Ng5Z9PB0
  EQrNND80QlWIlfoF6AC9p73t85FOvQsPG5GtOwo6tGBC6dsktmdANEPRlw8tFG6H
  IiVHBQRFUA5F1cMPzIdO+XUac4MUIXA+J9g/3cO3IcNcoPZ19VKbYDRo3s1uugz6
  7/2ItpYZK9rt8SmuUtR3bTA4pQu6FOgws2R9OnG4UAm0O4wYNWWbSAL992Eo5J8F
  WPU814yvqXuFJb2QPViYW+JAQnDLpA5UNvuGJ3xryss9jlOo4b2tgkzAZrpoirOq
  rgsUhNtsld3K4jLU0i4pVvFlvmPCqWJAXsxePDf5z/F4pwo8XUm8Faq7kk/eqZG6
  RL7iDA4yTuMXdGMporYaeTJbX7bW/VI7e13uU0X3vnjzT4KeWRv1ehjLYFG4ZTYP
  7H1aSGy7wS7qPsfg+9kB7ZJ9bQdQO1vJ1afTfq7i1O0kylj8edTSWebouxJq6+qX
  Lvh1bSvrOgclu7eMEMZ1qxX2zMuIdQgOOp56dEn9/VQq1dZqOlEGmpIMrLzjxswG

The format of the conf file is YAML. Here is what it looks like for a
made up example in plaintext.

  $ cat login-plaintext.conf
  # Login credentials for my site.
  #
  # You can choose a different login for each host
  # or the same login for multiple hosts.
  {
    'global' : ['admin', 'password', 22],
    'hosts'  : {
       'clack': ['tom', 'tappit'],
       'click': ['ray', 'cylinder'],
       'curly': ['choward', 'yipyipyip'],
       'larry': ['lhoward', 'stopitguys'],
       'moe': ['mhoward', 'knucklhead'],
       'batman': ['bwayne', 'darkknight'],
       'robin': ['dgrason', 'junior'],
       'superman': ['ckent', 'upupandaway'],
  
       'ldap-1': ['admin', 'secret', 21357],  # special port
       'ldap-2': ['admin', 'secret', 21357],  # special port
  
       'vms-1': ['admin', 'secret'],  # VM server
       'vms-2': ['admin', 'secret'],  # VM server
       'vms-3': ['admin', 'secret'],  # VM server
       'zfs-1': ['admin', 'secret'],  # file server, ZFS
    }
  }
  
You can create or modify a conf file using the rcmd_edit_conf.sh
utility. It uses another tool called rcmd_crypt.py that allows you
to encrypt/decrypt files using AES-256-CBC without having openssl
installed.

The batch file is a script that is executed on the remote host as a
series of commands. Here is what the batch file looks like for the
above example.

  $ cat -n check-disk-sub.sh
       1  #!/bin/bash
       2  DEVS=($(/usr/sbin/smartctl --scan | awk '{print $1;}'))
       3  OSTYPE=$(uname)
       4  if [[ "$OSTYPE" == "Linux" ]] ; then
       5      HN=$(hostname -s)
       6  elif [[ "$OSTYPE" == "SunOS" ]] ; then
       7      HN=$(hostname)
       8  fi
       9
      10  PROG=/usr/sbin/smartctl
      11  for DEV in ${DEVS[@]} ; do
      12      CAP=$($PROG -i $DEV | grep "User Capacity" | cut -c 19- | \
      13            sed -e 's/^.*\[//' -e 's/\]//')
      14      MODEL=$($PROG -i $DEV | grep "Device Model" | cut -c 19-)
      15      DATA=$($PROG -H $DEV | grep ^SMART | grep overall-health | \
      16             awk -F: '{print $2;}' | sed -e 's/^ *//')
      17  if [[ "$DATA" != "" ]] ; then
      18      printf "  %-9s %-5s %-19s " $HN $OSTYPE $DEV
      19      printf "%-8s %-23s %s\n" "$CAP" "$MODEL" "$DATA"
      20  fi
      21  done

For more information see the HELP.txt and examples subdirectory.

To see the license information use the -h option. It is GPLv3.
'''
import argparse
import datetime
import logging
import paramiko
import os
import re
import socket
import sys
import time
import yaml

from rcmd_crypt import decrypt
from getpass import getpass
from pprint import pprint

# Globals
logging.basicConfig()
LOGGER = logging.getLogger('rcmd')
VERSION = '1.0'


# ================================================================
# elapsed_time
# ================================================================
def elapsed_time(start, stop=None):
    '''
    Calculate and return the elapsed time in seconds.
    This was designed for older implementations that
    do not have the total_seconds method defined.

    Here is an example usage:

        start = datetime.datetime.now()
        time.sleep(0.5)
        print '%.2f seconds' % (elapsed_time(start))

    @param start  The start time.
    @param stop   The optional stop time (default: datetime.datetime.now()).
    @returns the elapsed time in seconds as a floating point number.
    '''
    if stop is None:
        stop = datetime.datetime.now()
    diff = stop - start
    secs = (diff.days * 3600 * 24)
    secs += diff.seconds
    secs += (float(diff.microseconds) / 1000000.)
    return secs


# ================================================================
# class RunRemoteCmd
# ================================================================
class RunRemoteCmd:
    '''
    Create an SSH connection to a server and execute commands.
    Here is a typical usage:

        ssh = RunRemoteCmd()
        ssh.connect('host', 'user', 'password', port=22)
        if ssh.connected() is False:
            sys.exit('Connection failed')

        # Run a command that does not require input.
        status, output = ssh.run('uname -a')
        print 'status = %d' % (status)
        print 'output (%d):' % (len(output))
        print '%s' % (output)

        # Run a command that does requires input.
        status, output = ssh.run('sudo uname -a', 'sudo-password')
        print 'status = %d' % (status)
        print 'output (%d):' % (len(output))
        print '%s' % (output)
    '''
    def __init__(self, compress=True, verbose=False):
        '''
        Setup the initial verbosity level and the logger.

        @param compress  Enable/disable compression.
        @param verbose   Enable/disable verbose messages.
        '''
        self.ssh = None
        self.transport = None
        self.compress = compress
        self.bufsize = 65536

        # Setup the logger
        self.logger = logging.getLogger('RunRemoteCmd')
        self.set_verbosity(verbose)

        self.hostname = None
        self.username = None
        self.port = 22

        fmt = '%(asctime)s RunRemoteCmd:%(funcName)s:%(lineno)d %(message)s'
        formatter = logging.Formatter(fmt)
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.info = self.logger.info
        self.info('created object')

    def __del__(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    def connect(self, hostname, username, password, port=22):
        '''
        Connect to the host.

        @param hostname  The hostname.
        @param username  The username.
        @param password  The password.
        @param port      The port (default=22).

        @returns True if the connection succeeded or false otherwise.
        '''
        self.info('connecting %s@%s:%d' % (username, hostname, port))
        self.hostname = hostname
        self.username = username
        self.port = port
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(hostname=hostname,
                             port=port,
                             username=username,
                             password=password)
            self.transport = self.ssh.get_transport()
            self.transport.use_compression(self.compress)
            self.info('succeeded: %s@%s:%d' % (username,
                                               hostname,
                                               port))
        except socket.error as exp:
            self.transport = None
            self.info('failed: %s@%s:%d: %s' % (username,
                                                hostname,
                                                port,
                                                str(exp)))
        except paramiko.BadAuthenticationType as exp:
            self.transport = None
            self.info('failed: %s@%s:%d: %s' % (username,
                                                hostname,
                                                port,
                                                str(exp)))
        except paramiko.AuthenticationException as exp:
            self.transport = None
            self.info('failed: %s@%s:%d: %s' % (username,
                                                hostname,
                                                port,
                                                str(exp)))

        return self.transport is not None

    def run(self, cmd, input_data=None, timeout=10):
        '''
        Run a command with optional input data.

        Here is an example that shows how to run commands with no input:

            ssh = RunRemoteCmd()
            ssh.connect('host', 'user', 'password')
            status, output = ssh.run('uname -a')
            status, output = ssh.run('uptime')

        Here is an example that shows how to run commands that require input:

            ssh = RunRemoteCmd()
            ssh.connect('host', 'user', 'password')
            status, output = ssh.run('sudo uname -a', '<sudo-password>')

        @param cmd         The command to run.
        @param input_data  The input data (default is None).
        @param timeout     The timeout in seconds (default is 10 seconds).
        @returns The status and the output (stdout and stderr combined).
        '''
        self.info('running command: (%d) %s' % (timeout, cmd))

        if self.transport is None:
            self.info('no connection to %s@%s:%s' % (str(self.username),
                                                     str(self.hostname),
                                                     str(self.port)))
            return -1, 'ERROR: connection not established\n'

        # Fix the input data.
        input_data = self._run_fix_input_data(input_data)

        # Initialize the session.
        self.info('initializing the session')
        session = self.transport.open_session()
        session.set_combine_stderr(True)
        session.get_pty()
        session.exec_command(cmd)
        output = self._run_poll(session, timeout, input_data)
        status = session.recv_exit_status()
        self.info('output size %d' % (len(output)))
        self.info('status %d' % (status))
        return status, output

    def connected(self):
        '''
        Am I connected to a host?

        @returns True if connected or false otherwise.
        '''
        return self.transport is not None

    def set_verbosity(self, verbose):
        '''
        Turn verbose messages on or off.

        @param verbose  Enable/disable verbose messages.
        '''
        if verbose > 0:
            self.logger.setLevel(logging.INFO)
        else:
            self.logger.setLevel(logging.ERROR)

    def _run_fix_input_data(self, input_data):
        '''
        Fix the input data supplied by the user for a command.

        @param input_data  The input data (default is None).
        @returns the fixed input data.
        '''
        if input_data is not None:
            if len(input_data) > 0:
                if '\\n' in input_data:
                    self.info('fixing user input')
                    # Convert \n in the input into new lines.
                    lines = input_data.split('\\n')
                    input_data = '\n'.join(lines)
            return input_data.split('\n')
        return []

    def _run_send_input(self, session, stdin, input_data):
        '''
        Send the input data.

        @param session     The session.
        @param stdin       The stdin stream for the session.
        @param input_data  The input data (default is None).
        '''
        if input_data is not None:
            self.info('session.exit_status_ready() %s' %
                      str(session.exit_status_ready()))
            self.info('stdin.channel.closed %s' % str(stdin.channel.closed))
            if stdin.channel.closed is False:
                self.info('sending input data')
                stdin.write(input_data)

    def _run_poll(self, session, timeout, input_data):
        '''
        Poll until the command completes.

        @param session     The session.
        @param timeout     The timeout in seconds.
        @param input_data  The input data.
        @returns the output
        '''
        interval = 0.1
        maxseconds = timeout
        maxcount = maxseconds / interval

        # Poll until completion or timeout
        # Note that we cannot directly use the stdout file descriptor
        # because it stalls at 64K bytes (65536).
        self.info('polling (%d, %d)' % (maxseconds, maxcount))
        input_idx = 0
        timeout_flag = False
        start = datetime.datetime.now()
        output = ''
        session.setblocking(0)
        while True:
            if session.recv_ready():
                data = session.recv(self.bufsize)
                output += data
                self.info('read %d bytes, total %d' % (len(data), len(output)))

                if session.send_ready():
                    # We received a potential prompt.
                    # In the future this could be made to work more
                    # like pexpect with pattern matching.
                    if input_idx < len(input_data):
                        data = input_data[input_idx] + '\n'
                        input_idx += 1
                        self.info('sending input data %d' % (len(data)))
                        session.send(data)

            self.info('session.exit_status_ready() = %s' %
                      (str(session.exit_status_ready())))
            if session.exit_status_ready():
                break

            # Timeout check
            secs = elapsed_time(start)
            self.info('timeout check %d %d' % (secs, maxseconds))
            if secs > maxseconds:
                self.info('polling finished - timeout')
                timeout_flag = True
                break
            time.sleep(0.200)

        self.info('polling loop ended')
        if session.recv_ready():
            data = session.recv(self.bufsize)
            output += data
            self.info('read %d bytes, total %d' % (len(data), len(output)))

        self.info('polling finished - %d output bytes' % (len(output)))
        if timeout_flag:
            self.info('appending timeout message')
            output += '\nERROR: timeout after %d seconds\n' % (timeout)
            session.close()

        return output


# ================================================================
# _login_global_update
# ================================================================
def _login_global_update(opts, logins, username, password, port, filename):
    '''
    Update the login global record.

    @param opts     The command line options.
    @param logins   The login credentials.
    @param username The username.
    @param password The password.
    @param port     The port number.
    @param filename The filename.
    @returns the updated login credentials.
    '''
    # Blindly overwrite the global data from the YAML file
    # but warn the user.
    _username = logins['global'][0]
    _password = logins['global'][1]
    _port = logins['global'][2]
    if _username is not None:
        if _username != username or _password != password or _port != port:
            msg = 'overwriting global login credentials: "%s" --> "%s" from %s'
            if opts.nowarn is False:
                LOGGER.warn(msg % (str(_username),
                                   str(username),
                                   filename))
            # Only overwrite if it changed.
            logins['global'] = [username, password, port, filename]
    else:
        logins['global'] = [username, password, port, filename]
    return logins


# ================================================================
# _login_host_update
# ================================================================
def _login_host_update(opts, logins, hostname, username, password,
                       port, filename):
    '''
    Update the login host record.

    @param opts     The command line options.
    @param logins   The login credentials.
    @param hostname The hostname.
    @param username The username.
    @param password The password.
    @param port     The port number.
    @param filename The filename.
    @returns the updated login credentials.
    '''

    # Allow the user to use the global defaults
    # by specifying empty strings.
    # Ex. -u user -p password --port 1234 -D newhost '' '' 0
    if username == '' and opts.user is not None:
        username = opts.user
    if password == '' and opts.password is not None:
        password = opts.password
    if port == 0:
        if opts.port is not None:
            port = int(opts.port)
        else:
            port = 22

    if hostname in logins['host']:
        _username = logins['host'][hostname][0]
        _password = logins['host'][hostname][1]
        if len(logins['host'][hostname]) > 2:
            _port = int(logins['host'][hostname][2])
        elif opts.port is not None:
            _port = int(opts.port)
        else:
            _port = 22
        if _username != username or _password != password or _port != port:
            msg = 'overwriting login credentials for host: '
            msg += '%s, "%s" --> "%s" from %s'
            if opts.nowarn is False:
                LOGGER.warn(msg % (hostname, _username,
                                   username, filename))

            # Only update if it changed.
            logins['host'][hostname] = [username, password, port, filename]
    else:
        logins['host'][hostname] = [username, password, port, filename]
    return logins


# ================================================================
# _load_login_data
# ================================================================
def _load_login_data(opts, logins, filename, input_data):
    '''
    Load the login file data.

    This function can be used for plaintext or encrypted data.

    @param opts        The command line options.
    @param logins      The login credentials.
    @param filename    The input file name for error reporting.
    @param input_data  The input data. For encrypted files,
                       this is the plaintext.
    @returns the updated login credentials.
    '''
    if input_data is None:
        LOGGER.error('no data from file: %s' % (filename))
        sys.exit(1)

    # Note the serious lack of structure syntax checking.
    yaml_data = yaml.load(input_data)

    if not isinstance(yaml_data, dict):
        LOGGER.error('no valid data found in file: %s' % (filename))
        sys.exit(1)

    # Make sure that the high level structure is okay.
    found = False
    for key in yaml_data:
        if key not in ['global', 'hosts']:
            LOGGER.error('unrecognized key (%s): %s' % (key, filename))
            sys.exit(1)
        else:
            found = True
    if not found:
        LOGGER.warning('no login data found in %s' % (filename))

    # Process the global record:
    # Two options:
    #   { "global": ["user", "password", "port"] ... }
    #   { "global": ["user", "password"] ... }
    if 'global' in yaml_data:
        _global = yaml_data['global']
        if not isinstance(_global, list):
            LOGGER.error('global entry is not a list: %s' % (filename))
            sys.exit(1)
        if len(_global) < 2 or len(_global) > 3:
            LOGGER.error('bad global list length (%d): %s' %
                         (len(_global), filename))
            sys.exit(1)

        username = _global[0]
        password = _global[1]
        if len(_global) > 2:
            port = int(_global[2])
        elif opts.port is not None:
            port = int(opts.port)
        else:
            port = 22

        kwargs = {
            'opts': opts,
            'logins': logins,
            'username': username,
            'password': password,
            'port': port,
            'filename': filename,
        }
        logins = _login_global_update(**kwargs)

    # Process the host record:
    # { "host": {"host1": ["user", "password", port],
    #            "host2": ["user", "password"],  # port=22 is the default
    #           }}
    if 'hosts' in yaml_data:
        _host = yaml_data['hosts']
        if not isinstance(_host, dict):
            LOGGER.error('host entry is not a dict: %s' % (filename))
            sys.exit(1)

        # Blindly add in all of the hosts.
        # Overwrite hosts that are already there but
        # generate a warning during the update operation.
        for host in _host:
            hostrec = _host[host]
            if not isinstance(hostrec, list):
                LOGGER.error('host entry %s is not a list: %s' %
                             (host, filename))
                sys.exit(1)

            if len(hostrec) > 3:
                LOGGER.error('bad host %s list length (%d): %s' %
                             (host, len(_global), filename))
                sys.exit(1)

            port = 22
            if opts.port is not None:
                port = int(opts.port)
            elif logins['global'][2] is not None:
                port = logins['global'][2]

            if len(hostrec) == 0:
                username = logins['global'][0]
                password = logins['global'][1]
            elif len(hostrec) == 1:
                username = logins['global'][0]
                password = hostrec[1]
            elif len(hostrec) == 2:
                username = hostrec[0]
                password = hostrec[1]
            else:
                username = hostrec[0]
                password = hostrec[1]
                if hostrec[2] != '*':
                    port = int(hostrec[2])

            if username == '*':
                username = logins['global'][0]
            if password == '*':
                password = logins['global'][1]

            kwargs = {
                'opts': opts,
                'logins': logins,
                'hostname': host,
                'username': username,
                'password': password,
                'port': port,
                'filename': filename,
            }
            logins = _login_host_update(**kwargs)
    return logins


# ================================================================
# _login_file
# ================================================================
def _login_file(opts, logins):
    '''
    Load the login credentials from a plaintext YAML file.

    Do not overwrite the global credentials if they are set.

    @param opts   The command line options.
    @param logins The login credentials.
    @returns the updated login credentials.
    '''
    if opts.login is not None:
        for item in opts.login:
            ifile = item[0]
            ifp = open(ifile, 'r')
            data = ifp.read()
            ifp.close()

            # Heuristic guess to determine whether this is an
            # encrypted file.
            password = None
            if data is not None:
                if data.find('{') < 0:
                    # This isn't a YAML file.
                    # assume that is it encrypted.
                    password = getpass('%s password: ' % (ifile))
                    try:
                        data = decrypt(password, data)
                    except Exception as exp:  # pylint: disable=W0703
                        LOGGER.error('decryption failed for file: %s (%s)' %
                                     (ifile, str(exp)))
                        sys.exit(1)

            try:
                logins = _load_login_data(opts, logins, ifile, data)
            except yaml.reader.ReaderError as exp:
                if password is not None:
                    LOGGER.error('load failed for file (invalid password?): %s (%s)' %
                                 (ifile, str(exp)))
                else:
                    LOGGER.error('load failed for file: %s (%s)' %
                                 (ifile, str(exp)))
                sys.exit(1)

    return logins


# ================================================================
# _login_file_encrypted
# ================================================================
def _login_file_encrypted(opts, logins):
    '''
    Load the login credentials from an encrypted YAML file.

    Encryption is done using openssl enc -e -a -aes-256-cbc -salt.

    Do not overwrite the global credentials if they are set.

    @param opts   The command line options.
    @param logins The login credentials.
    @returns the updated login credentials.
    '''
    if opts.login_secure is not None:
        for item in opts.login_secure:
            ifile = item[0]
            password = item[1]
            ifp = open(ifile, 'r')
            ciphertext = ifp.read()
            ifp.close()

            if password == '':
                password = getpass('%s password: ' % (ifile))
            try:
                plaintext = decrypt(password, ciphertext)
            except Exception as exp:  # pylint: disable=W0703
                LOGGER.error('decrypt failed for file: %s (%s)' %
                             (ifile, str(exp)))
                sys.exit(1)

            try:
                logins = _load_login_data(opts, logins, ifile, plaintext)
            except yaml.reader.ReaderError as exp:
                LOGGER.error('load failed for file (invalid password?): %s (%s)' %
                             (ifile, str(exp)))
                sys.exit(1)

    return logins


# ================================================================
# _login_cli
# ================================================================
def _login_cli(opts, logins):
    '''
    Load the login credentials from the CLI: -u and -p.

    @param opts   The command line options.
    @param logins The login credentials.
    @returns the updated login credentials.
    '''
    if opts.user is not None:
        username = opts.user
        if opts.password:
            password = opts.password
        else:
            password = getpass(opts.user + ' password: ')
        if opts.port is not None:
            port = int(opts.port)
        else:
            port = 22

        kwargs = {
            'opts': opts,
            'logins': logins,
            'username': username,
            'password': password,
            'port': port,
            'filename': 'CLI',
        }
        logins = _login_global_update(**kwargs)
    elif opts.password is not None:
        LOGGER.error('password specified with no user name')
        sys.exit(1)
    return logins


# ================================================================
# _login_defined_hosts
# ================================================================
def _login_defined_hosts(opts, logins):
    '''
    Load the login credentials from the -D host specifications.
    These are the highest priority.

    @param opts   The command line options.
    @param logins The login credentials.
    @returns the updated login credentials.
    '''
    if opts.define is not None:
        for host in opts.define:
            kwargs = {
                'opts': opts,
                'logins': logins,
                'hostname': host[0],
                'username': host[1],
                'password': host[2],
                'port': int(host[3]),
                'filename': 'DEFINE',
            }
            logins = _login_host_update(**kwargs)

    return logins


# ================================================================
# _load_login_credentials
# ================================================================
def _login_credentials(opts):
    '''
    Load the login credentials.

    @param opts  The command line options.
    @returns the login credentials.
    '''
    logins = {'global': [None, None, None],
              'host': {}}
    logins = _login_file(opts, logins)
    logins = _login_file_encrypted(opts, logins)
    logins = _login_cli(opts, logins)
    logins = _login_defined_hosts(opts, logins)

    if logins['global'][0] is None and len(logins['host']) == 0:
        LOGGER.error('no login credentials specified')
        sys.exit(1)

    return logins


# ================================================================
# _load_hosts
# ================================================================
def _load_hosts(opts, logins):
    '''
    Load the host information.

    This function loads all of the host information then filters
    out information provide in regular expressions or leading
    dashes.

    All of the host specifications are in the login data structure.
    It contains host names, regexs and negatives (-<host>).

    @param opts   The command line options.
    @param logins The login credentials.
    @returns the updated login credentials.
    '''

    # If no hosts were specified on the command line, then
    # use all hosts.
    hosts = {}  # use a dictionary for fast filtering lookup
    excluded_hosts = []
    regex_hosts = []
    regex_excluded_hosts = []
    if opts.host is not None:
        for hostnames in opts.host:
            # Handle the case where multiple hostnames are
            # specified in a comma separated list:
            #    -H host1,host2,host3
            # also
            #    -H '!host1,host2,host3'
            LOGGER.info('hostnames %s' % (hostnames))
            negate = False
            if hostnames[0] == '!':
                negate = True
                hostnames = hostnames[1:]
                LOGGER.info('negating host %s' % (hostnames[:1]))

            hostnames_list = hostnames.split(',')
            for host in hostnames_list:
                # Check to see whether this host is an re.
                # If it is store it for later.
                match = re.search('[\*\[\^\$]', host)
                if match:
                    if negate:
                        # Leading dash means exclude.
                        regex_excluded_hosts.append(host)
                    else:
                        regex_hosts.append(host)
                else:
                    if host in logins['host']:
                        username = logins['host'][host][0]
                        password = logins['host'][host][1]
                        port = int(logins['host'][host][2])
                    else:
                        username = logins['global'][0]
                        password = logins['global'][1]
                        if username is None or password is None:
                            msg = 'invalid login credentials for host: %s'
                            LOGGER.error(msg % (host))
                            sys.exit(1)
                        port = int(logins['global'][2])
                    if negate:
                        excluded_hosts.append(host)
                    else:
                        hosts[host] = [username, password, port]

    for regex_host in regex_hosts:
        # Search for matches in the login hosts that are not already
        # in the list.
        for loghost in logins['host']:
            if loghost not in hosts:
                match = re.search(regex_host, loghost)
                if match:
                    username = logins['host'][loghost][0]
                    password = logins['host'][loghost][1]
                    port = int(logins['host'][loghost][2])
                    hosts[loghost] = [username, password, port]

    # At this point, if no hosts have been added, use all of the login
    # hosts.
    if len(hosts) == 0:
        for loghost in logins['host']:
            username = logins['host'][loghost][0]
            password = logins['host'][loghost][1]
            port = int(logins['host'][loghost][2])
            hosts[loghost] = [username, password, port]

    # Now remove the hosts that were specifically excluded.
    if len(hosts):
        for excluded_host in excluded_hosts:
            if excluded_host in hosts:
                del hosts[excluded_host]

    # Now remove the hosts that were specifically excluded using
    # regex's.
    if len(hosts):
        for regex_host in regex_excluded_hosts:
            hosts_to_delete = []
            for host in hosts:
                match = re.search(regex_host, host)
                if match:
                    # Queue the hosts to delete.
                    # We don't want to disrupt the loop.
                    hosts_to_delete.append(host)

            # Now delete them.
            for host in hosts_to_delete:
                del hosts[host]

    return hosts


# ================================================================
# _load_cmds
# ================================================================
def _load_cmds(opts):
    '''
    Load the commands while preserving order.

    There are 4 types of command specifications:
        1. -c, a simple command string.
        2. -C, a command string + an input string.
        3. -b, a file of commands (batch).
        4. -B, a file of commands (batch) + a file of inputs.

    This function converts them to a 2-tuple: the command and the
    input that is used by the _runcmd function.

    @param opts     The command line options.
    @returns The command list.
    '''
    cmds = []
    if opts.cmd is not None:
        for cmd in opts.cmd:
            if isinstance(cmd, str):  # -c
                cmds.append([cmd, None])
            elif isinstance(cmd, file):  # -b
                cmd.seek(0)  # rewind
                cmds.append([cmd.read(), None])
            elif isinstance(cmd, list):
                assert len(cmd) == 2
                if isinstance(cmd[0], str):
                    cmds.append(cmd)
                elif isinstance(cmd[0], file):
                    cmd[0].seek(0)
                    cmd[1].seek(0)
                    cmds.append([cmd[0].read(), cmd[1].read()])
                else:
                    assert isinstance(cmd, str) or isinstance(cmd, file)
            else:
                assert isinstance(cmd, str) or isinstance(cmd, list)

    return cmds


# ================================================================
# runcmd
# ================================================================
def _runcmd(opts, cmd, rcmd, hostname, port, username):
    '''
    Run a single command.

    @param opts     The command line options.
    @param cmd      The command to run with input (2 element list).
    @param rcmd     The remote command execution object.
    @param hostname The hostname.
    @param port     The port.
    @param username The username.
    '''
    if opts.verbose:
        print
        print '# %s' % ('=' * 64)
        print '# Host    : %s' % (hostname)
        print '# Port    : %d' % (port)
        print '# User    : %s' % (username)
        if '\n' in cmd[0]:
            cmdstr = '\n' + cmd[0].rstrip()
            cmdstr = ('\n#           '.join(cmdstr.split('\n')))
            print '# Command : (%d) %s' % (len(cmd[0]), cmdstr.rstrip())
        else:
            print '# Command : %s' % (cmd[0])
        print '# Timeout : %d' % (opts.timeout)
        start = datetime.datetime.now()

    output = 'ERROR: could not connect to the server: %s\n' % (hostname)
    status = -1
    if rcmd.connected():
        status, output = rcmd.run(cmd[0], cmd[1], timeout=float(opts.timeout))

    if opts.verbose:
        secs = elapsed_time(start)
        print '# Status  : %d' % (status)
        print '# Size    : %d' % (len(output))
        print '# Time    : %.2f secs' % (secs)
        print '# %s' % ('=' * 64)

    sys.stdout.write('%s' % (output))
    sys.stdout.flush()

    return status, output


# ================================================================
# _runcmds
# ================================================================
def _listhosts(opts, hosts):
    '''
    List the hosts.

    This is useful for debugging and certain operations
    where you simply need to load all of the hosts from
    a conf file for individual processing.

    @param opts   The command line options.
    @param hosts  The hosts to operate on.
    '''
    if opts.list_hosts:
        for host in sorted(hosts, key=str.lower):
            print '%s' % (host)


# ================================================================
# _runcmds
# ================================================================
def _runcmds(opts, hosts):
    '''
    Run commands for all of the hosts.

    @param opts   The command line options.
    @param hosts  The hosts to operate on.
    '''
    cmds = _load_cmds(opts)
    if len(cmds):
        for host in sorted(hosts, key=str.lower):
            username = hosts[host][0]
            password = hosts[host][1]
            port = hosts[host][2]

            rcmd = RunRemoteCmd()
            if opts.verbose > 1:
                rcmd.set_verbosity(1)

            rcmd.connect(host, username, password, port)

            for cmd in cmds:
                status, output = _runcmd(opts, cmd, rcmd, host, port, username)
                if status and opts.exit_on_error:
                    break


# ================================================================
# _get_opts
# ================================================================
def _get_opts():
    '''
    Define and parse the command line options.

    @returns The options.
    '''
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

    # The cmd argument is set by the -b, -B, -c and -C options.
    # They use the same variable so that the input order can
    # be preserved.
    parser.add_argument('-b', '--batch',
                        action='append',
                        type=argparse.FileType('r'),
                        dest='cmd',
                        metavar=('CMD_FILE'),
                        help='batch commands')

    parser.add_argument('-B', '--batchi',
                        action='append',
                        nargs=2,  # append as a list
                        type=argparse.FileType('r'),
                        dest='cmd',
                        metavar=('CMD_FILE', 'INPUT_FILE'),
                        help='batch commands')

    parser.add_argument('-c', '--cmd',
                        action='append',
                        type=str,
                        dest='cmd',
                        metavar=('CMD_STRING'),
                        help='a command to execute')

    parser.add_argument('-C', '--cmdi',
                        action='append',
                        dest='cmd',
                        nargs=2,
                        metavar=('CMD_STRING', 'INPUT_STRING'),
                        help='a command to execute with input')

    parser.add_argument('-D', '--define',
                        action='append',
                        nargs=4,
                        metavar=('HOST', 'USER', 'PASSWORD', 'PORT'),
                        help='define host data on the command line')

    parser.add_argument('-e', '--exit_on_error',
                        action='store_true',
                        help='exit host if an error occurs')

    parser.add_argument('-H', '--host',
                        action='append',
                        help='host or comma separated list of hosts')

    parser.add_argument('--list-hosts',
                        action='store_true',
                        help='list the hosts explicitly')

    parser.add_argument('-l', '--login',
                        action='append',
                        nargs=1,
                        metavar=('FILE'),
                        help='login credentials file')

    parser.add_argument('-L', '--login-secure',
                        action='append',
                        nargs=2,
                        metavar=('ENCRYPTED_FILE', 'PASSWORD'),
                        help='secure login file with password')

    parser.add_argument('--nowarn',
                        action='store_true',
                        help='disable warnings')

    parser.add_argument('-p', '--password',
                        action='store',
                        help='the default user password')

    parser.add_argument('-P', '--port',
                        type=int,
                        default=22,
                        action='store',
                        help='the SSH port, default is 22')

    parser.add_argument('-t', '--timeout',
                        action='store',
                        type=float,
                        default=300,
                        metavar=('SECONDS'),
                        help='the command timeout, default is 300')

    parser.add_argument('-u', '--user',
                        action='store',
                        help='the default user name, overrides the login DB')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        help='the level of verbosity')

    parser.add_argument('-V', '--version',
                        action='version',
                        version='%(prog)s ' + VERSION)

    args = parser.parse_args()

    if args.verbose:
        print '''%s  Copyright(C) 2013  Joe Linoff
This program comes with ABSOLUTELY NO WARRANTY; for details type visit
http://www.gnu.org/licenses/.
This is free software, and you are welcome to redistribute it under
certain conditions; see the above web site for details.
''' % os.path.basename(__file__)

    if args.cmd is None and args.list_hosts is None:
        LOGGER.error('at least one command (-c or -C) must be specified')
        sys.exit(1)

    if args.cmd:
        for cmd in args.cmd:
            if isinstance(cmd, list) and len(cmd) == 1:
                if not os.path.exists(cmd[0]):
                    LOGGER.error('batch file does not exist: %s' % (cmd[0]))
                    sys.exit(1)

    if args.verbose > 2:
        pprint(args, indent=4)

    if args.verbose:
        LOGGER.setLevel(logging.INFO)
    return args


# ================================================================
# main
# ================================================================
def main():
    '''
    Run the program.
    '''
    opts = _get_opts()
    logins = _login_credentials(opts)
    hosts = _load_hosts(opts, logins)
    _listhosts(opts, hosts)
    _runcmds(opts, hosts)

# ================================================================
# MAIN
# ================================================================
if __name__ == '__main__':
    main()
