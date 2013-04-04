rcmd
====

This project contains a python tool that runs commands on remote hosts
using the SSH protocol (paramiko), an editing tool that automatically
decrypts/encrypts configuration data and examples that make it easy to
automate all sorts of different administration tasks especially when
it is used with an encrypted login configuration file.

Here is the list of available files/directories:

   File                   Brief Description
   =====================  ========================================
   bin/rcmd.py            The remote command execution tool.

   bin/rcmd_crypt.py      Tool used by rcmd_edit_conf.sh.

   bin/rcmd_edit_conf.sh  Tool edit encrypted conf files.

   examples/conf.sh       The configuration file for the examples.
                          You must edit this file to get the examples
                          to work. See the documentation in that file
        		  for additional information.

   examples/*.sh          Some example scripts.

   docs/                  Some additional documentation.

  
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
