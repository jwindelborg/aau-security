#!/usr/bin/env bash

pywareFile=/home/aau/aau-security/PyWare/PyWare.py
unuglifyjsBin=/home/aau/UnuglifyJS/bin/unuglifyjs
tConst=5
unuglyDir=~/MalwarePerformance/unuglifyjs
pywareDir=~/MalwarePerformance/pyware
baseMalPath=/home/aau/javascript-malware-collection
errorLog=/dev/null

mkdir -p $unuglyDir
mkdir -p $pywareDir

while read p; do
  out_name=${p##*/}
  timeout $tConst $unuglifyjsBin $baseMalPath$p > $unuglyDir/$out_name
  timeout $tConst $pywareFile $baseMalPath$p > $pywareDir/$out_name
done <all_malware
