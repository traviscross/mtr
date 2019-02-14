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

VERSION=$1
IN=$2
OUT=$3

#
#  MacOS's groff is missing .UR and .UE support, which makes
#  URL completely disappear from man pages.  We need to strip
#  those codes out when building for MacOS
#
if [ $(uname -s) = "Darwin" ]; then
   RMURUE='-e s/\.UR.//g -e s/\.UE//g'
else
   RMURUE=""
fi

sed -e "s|@VERSION[@]|$VERSION|g" $RMURUE $IN >$OUT
