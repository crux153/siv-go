#!/bin/sh
# Build a static BoringSSL libcrypto for the difffuzz_boringssl
# reference. Run it inside the golang:1.26 image from difffuzz/; it
# needs only git, python3, gcc and g++ (no cmake), using the source
# lists BoringSSL generates in gen/sources.json. The assembly files
# guard themselves by platform, so all but the Apple variants are
# compiled.
set -eu
cd "$(dirname "$0")"
TAG=0.20260929.0
COMMIT=427ec40cc8edc545253289232e885708c409e5ea
D=.cache/boringssl
[ -d $D/src ] || git clone -q --depth 1 --branch $TAG https://boringssl.googlesource.com/boringssl $D/src
[ "$(git -C $D/src rev-parse HEAD)" = $COMMIT ] || { echo "unexpected BoringSSL commit" >&2; exit 1; }
[ -f $D/libcrypto.a ] && [ -f $D/.built-$COMMIT ] && exit 0

rm -rf $D/obj && mkdir -p $D/obj
python3 - "$D/src" > $D/obj/sources <<'EOF'
import json, sys
d = json.load(open(sys.argv[1] + "/gen/sources.json"))
for k in ("bcm", "crypto"):
    for f in d[k].get("srcs", []) + [a for a in d[k].get("asm", []) if not a.endswith("-apple.S")]:
        print(f)
EOF
cd $D/src
xargs -P "$(nproc)" -I{} sh -c '
  f={}; o=../obj/$(echo "$f" | tr / _).o
  case "$f" in
    *.cc) g++ -std=c++17 -O2 -fPIC -DNDEBUG -Iinclude -c "$f" -o "$o" ;;
    *)    gcc -O2 -fPIC -DNDEBUG -Iinclude -c "$f" -o "$o" ;;
  esac' < ../obj/sources
cd ..
rm -f libcrypto.a && ar rcs libcrypto.a obj/*.o
rm -f .built-* && touch .built-$COMMIT
echo "built $(ls obj/*.o | wc -l) objects into $D/libcrypto.a"
