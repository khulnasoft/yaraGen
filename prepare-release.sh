#!/bin/bash

RELDIR=./release
OUTDIR=$RELDIR/yaraGen/

cp yaraGen.py $OUTDIR
cp -r 3rdparty $OUTDIR
cp -r lib $OUTDIR
cp README.md $OUTDIR
cp LICENSE $OUTDIR

cd $RELDIR
tar -cvzf yaraGen.tar.gz ./yaraGen/
cd ..
