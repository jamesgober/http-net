#!/usr/bin/env bash
# Interleaved A/B benchmarks: the working tree against a git ref (a release
# tag by default), the two builds run alternately so machine load falls on
# both, pinned to one core when `taskset` exists. Prints the median of each
# side per benchmark and the difference. The 5% regression gate
# (docs/PERFORMANCE.md) reads this output: a hot-path bench whose median is
# more than 5% slower blocks the change.
#
#   scripts/bench_ab.sh [ref] [rounds] [filter ...]
#   scripts/bench_ab.sh v0.6.0 5 request_head response_write/five_fields
#
# Defaults: the latest tag, 5 rounds, every hot-path bench.
set -eu

root=$(git rev-parse --show-toplevel)
ref=${1:-$(git -C "$root" describe --tags --abbrev=0)}
rounds=${2:-5}
shift $(($# < 2 ? $# : 2))
filters=${*:-"request_head pipelined response_parse response_write/five_fields body_1mib/content body_1mib/chunked"}
core=${BENCH_CORE:-3}

work=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$work/base" >/dev/null 2>&1 || true; rm -rf -- "$work"' EXIT
git -C "$root" worktree add --detach "$work/base" "$ref" >/dev/null

build() {
    # Builds the bench in "$1" and prints the executable's absolute path.
    local exe
    exe=$(cd "$1" && cargo bench --bench bench --no-run 2>&1 | sed -n 's/.*Executable[^(]*(\(.*\)).*/\1/p' | tail -1)
    case "$exe" in
        "") echo "no bench executable built in $1" >&2; exit 1 ;;
        /*) echo "$exe" ;;
        *) echo "$1/$exe" ;;
    esac
}
base_exe=$(build "$work/base")
new_exe=$(build "$root")

pin=()
if command -v taskset >/dev/null; then
    pin=(taskset -c "$core")
fi

run() {
    # One measurement: the median of the first matching benchmark.
    ${pin[@]+"${pin[@]}"} "$1" --bench --noplot --measurement-time 3 --warm-up-time 1 "$2" 2>&1 \
        | awk '/time:/ && !/%/ { for (i = 1; i <= NF; i++) if ($i == "time:") { print $(i + 3), $(i + 4); exit } }'
}

echo "base $ref, $rounds rounds, core ${pin[*]:+$core}"
for filter in $filters; do
    for round in $(seq 1 "$rounds"); do
        echo "$filter old $(run "$base_exe" "$filter")"
        echo "$filter new $(run "$new_exe" "$filter")"
    done
done | awk '
    function ns(v, u) {
        if (u == "ps") return v / 1000
        if (u == "ns") return v
        if (u == "ms") return v * 1e6
        if (u == "s") return v * 1e9
        return v * 1000
    }
    function median(list, n,    i, j, t) {
        for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (list[j] < list[i]) { t = list[i]; list[i] = list[j]; list[j] = t }
        return n % 2 ? list[(n + 1) / 2] : (list[n / 2] + list[n / 2 + 1]) / 2
    }
    {
        key = $1 SUBSEP $2
        count[key]++
        value[key, count[key]] = ns($3, $4)
        names[$1] = 1
    }
    END {
        for (name in names) {
            no = count[name, "old"]; nn = count[name, "new"]
            for (i = 1; i <= no; i++) o[i] = value[name, "old", i]
            for (i = 1; i <= nn; i++) n[i] = value[name, "new", i]
            mo = median(o, no); mn = median(n, nn)
            over = ((mn - mo) / mo > 0.05) ? "  OVER THE 5% GATE" : ""
            printf "%-30s old %12.1f ns  new %12.1f ns  %+6.1f%%%s\n", name, mo, mn, 100 * (mn - mo) / mo, over
        }
    }'
