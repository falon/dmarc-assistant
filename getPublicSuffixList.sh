#!/bin/sh
LIST=https://publicsuffix.org/list/public_suffix_list.dat
DEST=/usr/local/psl/psl.dat

wget $LIST -O $DEST
