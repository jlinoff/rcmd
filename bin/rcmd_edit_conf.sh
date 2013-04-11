#!/bin/bash

#
# Edit the conf file.
#
function _help()
{
    cat <<EOF
usage: $BN [-h] [-e EDITOR] CONF_FILE


description:

  This tool uses rcmd_crypt.py to allow you to edit an encrypted login
  conf file. If the file doesn't exist, it is created from a template.

  This is how you use it:

    $BN login.conf

  It uses the EDITOR environment variable if it is defined. If it
  isn't, it defaults to vi. You can manually specify an editor on the
  command line use the -e option as shown in the example below.

    $BN -e emacs login.conf

  The login conf file has two top level records: global and hosts. The
  global record defines the login credentials to use for any host that
  is not defined in the host section. The hosts section contains the
  login credentials for specific hosts. 

  The data in both cases is the username, password and, optionally,
  the port. You can use '*' in host username and password fields to
  designate the use of the corresponding global values.

  Here is an example login.conf file.

    \$ cat login.conf
    # Login credentials for my site.
    #
    # You can choose a different login for each host
    # or the same login for multiple hosts.
    {
      'global' : ['admin', 'thebigsecret', 22],
      'hosts'  : {
           'clack'   : ['root', 'therootpassword'],  # special login
           'click'   : [],  # use the defaults
           'curly'   : ['*', 'curlysbigsecret'],  # different password
           'larry'   : ['*', '*'],  # use the defaults
           'moe'     : [],
           'batman'  : [],
           'robin'   : [],
           'superman': [],
  
           'ldap-1'  : ['madman', 'nailfilers', 21357],  # special port
           'ldap-2'  : ['madman', 'nailfilers', 21357],  # special port
  
           'vms-1': [],  # VM server
           'vms-2': [],  # VM server
           'vms-3': [],  # VM server

           'zfs-1': [],  # file server, ZFS
           'zfs-2': [],  # file server, ZFS
        }
      }

  Even though it is available, I would not recommend specifying the
  password on the command line using the -p option because it is
  available in the history file.


optional arguments:
  -h, --help              show this help message and exit
  -e EDITOR, --editor EDITOR
                          manually specify an editor
  -p PASSWORD, --password PASSWORD
                          manually specify the password
  -v, --verbose           the level of verbosity
  -V, --version           show the programs version and exit


author:
  Joe Linoff

EOF
    exit 0
}

# Collect the options.
if [[ "$EDITOR" == "" ]] ; then
    EDITOR=vi
fi
PASSWORD=""
CONF=""
BN=$(basename $0)
VERBOSE=0

# Load the crypt tool.
medir=$(dirname -- $(readlink -f $0))
cryptor="$medir/rcmd_crypt.py"
if [ ! -f $cryptor ] ; then
    echo "ERROR: file not found: $cryptor"
    exit 1
fi


while (( $# > 0 )) ; do
    arg="$1"
    shift
    case $arg in
	-e|--editor)
	    EDITOR="$1"
	    shift
	    ;;
	-h|--help)
	    _help
	    ;;
	-p|--password)
	    PASSWORD="$1"
	    shift
	    ;;
	-v,|--verbose)
	    VERBOSE=$(($VERBOSE + 1))
	    ;;
	-V|--version)
	    echo "$BN v1.0"
	    exit 0
	    ;;
	*)
	    if [[ "$CONF" != "" ]] ; then
		echo "ERROR: conf was already specified: $CONF"
		exit 1
	    fi
	    CONF="$arg"
	    ;;
    esac
done

if [[ "$CONF" == "" ]] ; then
    echo "ERROR: login conf file not specified"
    exit 1
fi

if (( $VERBOSE )) ; then
    echo "conf  : $CONF"
    echo "crypto: $crypto"
    echo "medir : $medir"
fi

# The conf file doesn't exist.
BACKUP=1
if [ ! -f "$CONF" ] ; then
    # First get the passwords.
    BACKUP=0
    echo "Creating login conf file: $CONF"
    if [[ "$PASSWORD" == "" ]] ; then
	while (( 1 )) ; do
	    read -s -p "Password: " PASSWORD
	    echo
	    read -s -p "Confirm:  " check
	    echo
	    if [[ "$PASSWORD" == "$check" ]] ; then
		break
	    fi
	    echo "WARNING: password and confirmation do not match."
	    echo "         please try again."
	done
    fi

    # Now create the template file.
    cat >$CONF <<EOF
# Login conf file for rcmd.
{
    'global' : ['username', 'password', 22],
    'hosts' : {
        #'hostname1' : [],  # use the global defaults
        #'hostname2' : ['*', password2],  # use the global default for username
        #'hostname3' : ['*', '*'],  # global default for username and password
        #'hostname4' : ['*', '*', 12345],  # global defaults with custom port
        #'hostname5' : ['username5', 'password5'],  # port=22 is the default
        #'hostname6' : ['username6', 'password6', port], 
    }
}
EOF
    chmod 0600 $CONF
    $cryptor -e -p "$PASSWORD" -i $CONF -o $CONF
fi

# Do we need to decrypt?
if ! grep -q '{' $CONF ; then
    if (( $VERBOSE )) ; then
	echo "login conf is encrypted"
    fi

    # YES
    if [[ "$PASSWORD" == "" ]] ; then
	read -s -p "Password: " PASSWORD
	echo
    fi
    cp $CONF $CONF.bak
    $cryptor -d -p "$PASSWORD" -i $CONF -o $CONF.tmp
    st=$?
    if (( $st )) ; then
	rm -f $CONF.tmp
	echo "ERROR: decrypt operation failed for $CONF."
	exit 1
    fi

    # Check the file
    if ! grep -q 'global' $CONF.tmp ; then
	if ! grep -q 'hosts' $CONF.tmp ; then
	    rm -f $CONF.tmp
	    echo "ERROR: invalid password, decrypt operation failed for $CONF."
	    exit 1
	fi
    fi
    mv $CONF.tmp $CONF
else
    # Check the file
    if ! grep -q 'global' $CONF ; then
	if ! grep -q 'hosts' $CONF ; then
	    echo "ERROR: invalid password, decrypt operation failed for $CONF."
	    exit 1
	fi
    fi
fi

# Edit the file.
if (( $BACKUP )) ; then
    # Don't backup when first created.
    cp $CONF $CONF.bak
fi
$EDITOR $CONF
if [[ "$PASSWORD" == "" ]] ; then
    read -s -p "Password: " PASSWORD
    echo
fi
$cryptor -e -p "$PASSWORD" -i $CONF -o $CONF
st=$?
if (( $st )) ; then
    echo "ERROR: encrypt operation failed for $CONF."
    exit 1
fi

