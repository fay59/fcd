#!/usr/bin/env bash

if (( $# < 1 )); then
    echo "Usage: $0 <file to decompile> [fcd options]"
    exit 1
fi

BINARY=$1
OPTS=${@:1:$#-1}
# do not change /workspace
docker run --rm -v $(dirname $(realpath $BINARY)):/workspace fcd fcd $OPTS /workspace/$(basename $BINARY) 