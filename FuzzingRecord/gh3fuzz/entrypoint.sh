#!/bin/sh

# IN CASE OF FIRE BREAK GLASS
# if anything goes wrong with docker remove these damn redirects!
dockerd-entrypoint.sh >/dev/null 2>/dev/null &

while ! docker ps >/dev/null 2>/dev/null; do
	echo Waiting for startup...
	sleep 1
	if [ -z "$(jobs)" ]; then
		echo 'Failed to start docker!'
		exit 1
	fi
done
echo 'Started up!'

exec "$@"
