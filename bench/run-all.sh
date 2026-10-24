#!/bin/bash
# The benchmark matrix behind README's numbers.
cd "$(dirname "$0")"
for w in 1 2 4; do
  ./pg-bench.sh $w 10 15     # 15,360 flows: cache-resident working set
  ./pg-bench.sh $w 14 61     # 999,424 flows: 1M sessions, every packet a different session
done
