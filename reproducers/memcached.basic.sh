#! /bin/bash

# Tests memcache
memtier_benchmark -p 11211 -t 4 -c 4 --ratio=1:1 --protocol=memcache_test

