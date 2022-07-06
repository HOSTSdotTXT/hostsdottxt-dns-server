#!/usr/bin/env bash

cargo build --release

for ns in ns{1..4}.fdns.dev; do
        scp target/release/dns-server root@$ns:/tmp/coredns
        ssh root@$ns << EOF
                systemctl stop coredns && mv /tmp/coredns /usr/local/sbin/coredns && systemctl start coredns
EOF

done
