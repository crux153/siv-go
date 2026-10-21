#!/usr/bin/env bash
# One-shot status of the differential fuzzing run.
cd "$(dirname "$0")"
echo "time: $(date '+%F %T %Z')  load: $(cut -d' ' -f1-3 /proc/loadavg)"
docker ps -a --filter name=sivfuzz- --format '{{.Names}} {{.Status}}'
for n in aead segment sealerops; do
  last=$(grep -a 'fuzz: elapsed' "logs/$n.log" 2>/dev/null | tail -1)
  fail=$(grep -a -m1 -E -- '--- FAIL|panic:|Failing input' "logs/$n.log" 2>/dev/null)
  echo "$n: ${last:-no progress yet}${fail:+  FAIL: $fail}"
done
echo "wraphunt: $(tail -1 logs/wraphunt.progress 2>/dev/null || echo 'no progress yet')"
grep -a -m3 'WRAPHUNT FAILURE' logs/wraphunt.log 2>/dev/null
for d in testdata/fuzz/*/; do [ -d "$d" ] && echo "corpus/crashers $(basename "$d"): $(ls "$d" | wc -l) file(s)"; done
echo "failures dir: $(ls failures 2>/dev/null | wc -l) file(s)"
