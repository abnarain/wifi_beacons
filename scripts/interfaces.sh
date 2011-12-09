#!/bin/sh 

FINAL_DIR="/tmp/sniffer/updates"
STAGING_DIR="/tmp/sniffer/stage"


if [ -d "$SUBMISSIONS_DIR" -a "$(ls -A $SUBMISSIONS_DIR)" ]; then
    mkdir -p $STAGING_DIR
    mv $SUBMISSIONS_DIR/* $STAGING_DIR
    sleep 3


    TEMP_MANIFEST=$STAGING_DIR/unchecksummed.tar
    rm -f $TEMP_MANIFEST
    (cd $STAGING_DIR && tar cvf $TEMP_MANIFEST *.gz)
    MANIFEST_FILE=$STAGING_DIR/`cat /etc/bismark/ID`_`date +%F_%H-%M-%S`_`md5sum $TEMP_MANIFEST | cut -d" " -f 1`.tar
    mv $TEMP_MANIFEST $MANIFEST_FILE
    scp -S "/tmp/bismark/ssh" -i $SSH_KEY $MANIFEST_FILE $USER@$SERVER:$WIRELESS_DATA_PATH && rm $STAGING_DIR/*
    rm -f $MANIFEST_FILE
fi