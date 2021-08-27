#!/bin/sh

domain=framagit.org
type=AAAA
if [ "$1" != "" ]; then
    domain=$1
    if [ "$2" != "" ]; then
	type=$2
    fi
fi
echo "DoT"
for server in $(cat dot-servers.txt); do
    echo ""
    echo $server
    ./remoh.py --check --dot $server $domain $type
done
echo ""
echo "DoH"
for url in $(cat doh-servers.txt); do
    echo ""
    echo $url
    ./remoh.py --check $url $domain $type
done

