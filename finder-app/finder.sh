#!/bin/sh

filesdir=$1
searchstr=$2

if [ -z "${filesdir}" ]; then
    echo "filesdir not specified"
    exit 1
fi

if [ -z "${searchstr}" ]; then
    echo "searchstr not specified"
    exit 1
fi

if [ ! -d "${filesdir}" ]; then
    echo "${filesdir} is not a directory"
    exit 1
fi

# Get the number of files
num_files=$(find ${filesdir} -type f | wc -l)

# Get the number of matching lines
matching_lines=$(grep -Rn ${searchstr} ${filesdir}/* | wc -l)

echo "The number of files are ${num_files} and the number of matching lines are ${matching_lines}"
