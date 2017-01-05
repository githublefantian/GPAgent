#!/bin/bash

OTHERFILES="web/ "

VERSION=`git describe`
AGENT_DIR="agent-$VERSION"
DATE=`date +%Y%m%d`
ARCHIVE_NAME="agent-${VERSION}-$DATE.tar.gz"

cd agent
git archive --format=tar --prefix=$AGENT_DIR/ ${VERSION} | gzip > $ARCHIVE_NAME
mv $ARCHIVE_NAME ..

cd ..
tar -xzf $ARCHIVE_NAME && rm -rf $ARCHIVE_NAME
tar -czf $ARCHIVE_NAME $AGENT_DIR/ ${OTHERFILES} && rm -rf $AGENT_DIR/
mv -f $ARCHIVE_NAME UserManual/
[ $? -eq 0 ] && echo "archive [$ARCHIVE_NAME] success!" && exit
echo "archive release version failed!"
