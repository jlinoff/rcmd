# rcmd configuration

# Define the system directories.
if [[ "$RCMD_DIR" == "" ]] ; then
    RCMD_DIR=$(dirname $(dirname -- $(readlink -f $0)))
fi
RCMD_BIN_DIR="$RCMD_DIR/bin"
RCMD_EXAMPLES_DIR="$RCMD_DIR/examples"

# Define the system files.
RCMD="$RCMD_BIN_DIR/rcmd.py"
RCMD_CRYPT="$RCMD_BIN_DIR/rcmd_crypt.py"
RCMD_EDIT="$RCMD_BIN_DIR/rcmd_edit_conf.sh"


# Local conf data.
# To set it up for local use:
#
#   1. Edit the example.conf.password file and add a custom
#      password. The default is secret. You don't have to
#      change if you don't want to but please make sure
#      that is not readable by anyone but you.
#      $ echo 'secret' >conf.pass
#
#   2. Edit the example.conf.txt file and add your
#      your host information.
#      $ ../bin/rcmd_conf_edit.sh -e emacs -p "`cat conf.pass`" conf.dat
#      $ chmod 0600 conf.dat
#
RCMD_CONF="$RCMD_EXAMPLES_DIR/conf.dat"
RCMD_PASSFILE="$RCMD_EXAMPLES_DIR/conf.pass"

# Existence checks.
REQ_DIRS=($RCMD_DIR $RCMD_BIN_DIR $RCMD_EXAMPLES_DIR)
for REQ_DIR in ${REQ_DIRS[@]} ; do
    if [ ! -d $REQ_DIR ] ; then
	echo "ERROR: directory not found: $REQ_DIR"
	exit 1
    fi
done

REQ_FILES=($RCMD $RCMD_CRYPT $RCMD_EDIT $RCMD_PASSFILE $RCMD_CONF)
for REQ_FILE in ${REQ_FILES[@]} ; do
    if [ ! -f $REQ_FILE ] ; then
	echo "ERROR: file not found: $REQ_FILE"
	exit 1
    fi
done

# Useful variables.
RCMD_PASS="`cat $RCMD_PASSFILE`"
RCMDL="$RCMD -L $RCMD_CONF $RCMD_PASS"
