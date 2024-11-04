#!/bin/bash

writefile=$1
writestr=$2

if [ -z "${writefile}" ]; then
    echo "filesdir not specified"
    exit 1
fi

if [ -z "${writestr}" ]; then
    echo "searchstr not specified"
    exit 1
fi

if [ ! -f "${writefile}" ]; then
    file_path=$(dirname ${writefile})
    mkdir -p ${file_path}
fi

echo ${writestr} > ${writefile}

if [ ! -f "${writefile}" ]; then
    echo "Failed to create file ${writefile}"
    exit 1
fi
