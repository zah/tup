#! /bin/sh -e
# tup - A file-based build system
#
# Copyright (C) 2012-2015  Mike Shal <marfey@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Make sure we can't use a variant file as an input.
. ./tup.sh

tmkdir build
cat > Tupfile << HERE
: |> touch %o |> foo
HERE
tup touch Tupfile build/tup.config
update

cat > Tupfile << HERE
: |> touch %o |> foo
ifeq (@(FOO),1)
: ../build/foo |> cat %f > %o |> output
endif
HERE
tup touch Tupfile
update

tmkdir build2
cat > build2/tup.config << HERE
CONFIG_FOO=1
HERE
update_fail_msg "Unable to use files from another variant.*in this variant"

eotup
