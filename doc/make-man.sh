#!/bin/sh

pod2man --section=5 --release=' ' --center=' ' edg-mkgridmap.conf.pod > \
    edg-mkgridmap.conf.5
pod2man --section=8 --release=' ' --center=' ' edg-mkgridmap.pod > \
    edg-mkgridmap.8
