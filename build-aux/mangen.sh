#!/bin/sh

#
#  Generate the man pages.
#
#  We are just here to substitute the @VERSION@ string with our real version.
#

if [ $# -lt 3 ]; then
    echo Usage: mangen.sh VERSION IN OUT
    exit 1
fi

TMP_FILE=/tmp/mangen.$$

sed -e "s|@VERSION[@]|$1|g" $2 >$TMP_FILE

#
#  MacOS's groff is missing .UR and .UE support, which makes
#  URL completely disappear from man pages.  We need to strip
#  those codes out when building for MacOS
#
if [ $(uname -s) = "Darwin" ]; then
    sed -e "s|.UR ||g" $TMP_FILE | sed -e "s|.UE||g" > $3
else
    cp $TMP_FILE $3
fi

rm -f $TMP_FILE
