#!/bin/bash
HORIZONTAL_DELIM='----------------'
for test_script in $(ls | grep test_); do
	echo $HORIZONTAL_DELIM
	echo running $test_script
	echo $HORIZONTAL_DELIM
	"./$test_script"
done
