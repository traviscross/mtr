#!/bin/sh
#
#   mtr  --  a network diagnostic tool
#   Copyright (C) 2026  Darafei Praliaskouski
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#

set -eu

distdir=mtr-dist-version-test
expected_version=$(build-aux/git-version-gen .tarball-version)

cleanup() {
    rm -rf "$distdir"
}
trap cleanup EXIT INT TERM

cleanup
"${MAKE:-make}" distdir distdir="$distdir" >/dev/null

test -f "$distdir/.tarball-version"
actual_version=$(cat "$distdir/.tarball-version")
test "$actual_version" = "$expected_version"

configure_version=$("$distdir/configure" --version | sed -n '1p')
test "$configure_version" = "mtr configure $expected_version"
