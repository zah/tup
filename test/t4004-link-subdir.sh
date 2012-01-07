#! /bin/sh -e
# tup - A file-based build system
#
# Copyright (C) 2008-2012  Mike Shal <marfey@gmail.com>
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

. ./tup.sh

cat > Tupfile << HERE
: foreach *.c |> gcc -c %f -o %o |> %B.o
: *.o fs/built-in.o |> gcc %f -o prog |> prog
HERE

tmkdir fs
cat > fs/Tupfile << HERE
: foreach *.c |> gcc -c %f -o %o |> %B.o
: *.o |> ld -r %f -o built-in.o |> built-in.o
HERE

echo "int main(void) {return 0;}" > main.c
echo "void ext3fs(void) {}" > fs/ext3.c
echo "void ext4fs(void) {}" > fs/ext4.c

tup touch Tupfile main.c fs/ext3.c fs/ext4.c fs/Tupfile
update

sym_check prog main ext3fs ext4fs

eotup
