#!/bin/sh

wget https://github.com/stathissideris/ditaa/releases/download/v0.11.0/ditaa-0.11.0-standalone.jar
for name in *.ditaa; do
    java -jar ditaa-0.11.0-standalone.jar --svg --no-shadows $name ${name%.*}.svg
    sed -i -e "s/font-family='[^']*'/font-family='monospace'/" ${name%.*}.svg
done
rm -f ditaa-0.11.0-standalone.jar
