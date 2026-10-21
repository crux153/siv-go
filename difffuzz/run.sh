#!/usr/bin/env bash
# Launch the differential fuzzing containers. Usage: ./run.sh <end-epoch>
set -euo pipefail
cd "$(dirname "$0")"
END=${1:?end epoch}
DUR=$(( END - $(date +%s) ))
[ "$DUR" -gt 60 ] || { echo "end time too close"; exit 1; }
mkdir -p logs failures .cache
IMG=golang:1.26
common=(--user "$(id -u):$(id -g)" --cpu-shares 256
  -v "$(cd .. && pwd)":/src -w /src/difffuzz
  -e HOME=/tmp -e GOCACHE=/src/difffuzz/.cache/go-build
  -e GOMODCACHE=/src/difffuzz/.cache/mod -e GOFLAGS=-modcacherw
  -e GOTOOLCHAIN=local -e DIFFFUZZ_FAILDIR=/src/difffuzz/failures)

# Warm the module and build caches once.
docker run --rm "${common[@]}" "$IMG" sh -c 'go mod download && go vet . && go test -c -o /dev/null .'

fuzz() { # name target parallel
  docker run -d --name "sivfuzz-$1" "${common[@]}" "$IMG" \
    sh -c "go test -run '^\$' -fuzz '^$2\$' -fuzztime ${DUR}s -parallel $3 . > logs/$1.log 2>&1"
}
fuzz aead FuzzAEAD 28
fuzz segment FuzzSegment 36
fuzz sealerops FuzzSealerOps 12
docker run -d --name sivfuzz-wraphunt "${common[@]}" \
  -e WRAPHUNT=${DUR}s -e WRAPHUNT_WORKERS=36 -e WRAPHUNT_LOG=/src/difffuzz/logs/wraphunt.progress "$IMG" \
  sh -c "go test -count=1 -run '^TestWrapHunt\$' -timeout 0 -v . > logs/wraphunt.log 2>&1"
echo "started for ${DUR}s (until $(date -d @"$END"))"
