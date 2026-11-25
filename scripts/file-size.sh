#!/usr/bin/env bash
# Checks source file sizes and folder code shape across tracked Rust, Swift,
# and TypeScript sources under crates/, extension/src, and site/src (inline
# #[cfg(test)] items are excluded; test-only files are measured separately).
#   warn  > 800 non-test lines
#   error > 1500 non-test lines, unless scripts/file-size-exceptions.txt lists a
#         ceiling for the file ("<path> <ceiling>"; ceilings only go down)
#   warn  > 1000 lines in a test file or inline test module
#   error prefix families (x.rs/x/ + >=2 x_*.rs or >=3 x_*.rs, excluding
#         examples/, benches/, bin/; x.ts/x/ + >=2 x-*.ts/x_*.ts or >=3
#         x-*.ts/x_*.ts, .tsx included; tests excluded)
#   warn  > 40 non-test source files in a folder
#   error > 60 non-test source files in a folder
# Usage: scripts/file-size.sh [--warn-only] [--update-exceptions [--allow-raise]]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SOFT=800 HARD=1500 TESTCAP=1000 FOLDER_SOFT=40 FOLDER_HARD=60
EXC=scripts/file-size-exceptions.txt
FOLDER_EXC=scripts/folder-shape-exceptions.txt
warn_only=0 update=0 raise=0
for a in "$@"; do
  case "$a" in
    --warn-only) warn_only=1 ;;
    --update-exceptions) update=1 ;;
    --allow-raise) raise=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

measure() {
  git ls-files -z 'crates/*.rs' 'crates/*.swift' 'extension/src/*.ts' 'site/src/*.ts' 'site/src/*.tsx' | xargs -0 awk '
    function reset() { prod = 0; test = 0; st = 0; depth = 0; maxtest = 0; cur = 0 }
    function braces(s,   t, o, c) {
      gsub(/\\./, "", s); gsub(/"[^"]*"/, "", s); gsub(/\047.\047/, "", s)
      sub(/\/\/.*/, "", s)
      t = s; o = gsub(/\{/, "", t); t = s; c = gsub(/\}/, "", t)
      return o - c
    }
    function flush() {
      if (name != "") {
        if (cur > maxtest) maxtest = cur
        printf "%s %d %d %d\n", name, prod, test, maxtest
      }
    }
    FNR == 1 {
      flush(); reset(); name = FILENAME
      skip = (FILENAME ~ /(^|\/)node_modules\// || FILENAME ~ /^extension\/src\/gen\// || FILENAME ~ /\.d\.ts$/ || FILENAME ~ /\.(generated|gen|g|pb)\.(rs|tsx?|swift)$/ || FILENAME ~ /_generated\.rs$/)
      if (skip) { name = ""; next }
      isrs = (FILENAME ~ /\.rs$/)
      testfile = (FILENAME ~ /(^|\/)(tests?|benches|e2e|__tests__)\// || FILENAME ~ /(^|\/)[^\/]*Tests\// || FILENAME ~ /(^|\/)tests?\.rs$/ || FILENAME ~ /_tests?\.rs$/ || FILENAME ~ /\.(test|spec)\.tsx?$/ || FILENAME ~ /Tests\.swift$/)
    }
    {
      if (name == "") next
      if (testfile) { test++; cur++; next }
      if (!isrs) { prod++; next }
      if (st == 0) {
        if ($0 ~ /^[ \t]*#\[cfg\(test\)\]/) { st = 1; cur = 1; test++; next }
        prod++; next
      }
      test++; cur++
      if (st == 1) {                      # attribute seen, find the item head
        if ($0 ~ /^[ \t]*#\[/) next
        d = braces($0)
        if (d > 0 || $0 ~ /\{/) { depth = d; st = (depth > 0) ? 2 : 0 }
        else if ($0 ~ /;[ \t]*$/) st = 0
        if (st == 0) { if (cur > maxtest) maxtest = cur; cur = 0 }
        next
      }
      depth += braces($0)
      if (depth <= 0) { st = 0; if (cur > maxtest) maxtest = cur; cur = 0 }
    }
    END { flush() }'
}

check_shape() {
  git ls-files | awk -v fsoft="$FOLDER_SOFT" -v fhard="$FOLDER_HARD" '
    function dirname_of(p,   i) {
      i = match(p, /\/[^\/]+$/)
      return i ? substr(p, 1, i - 1) : "."
    }
    function basename_of(p,   i) {
      i = match(p, /\/[^\/]+$/)
      return i ? substr(p, i + 1) : p
    }
    {
      p = $0
      if (p == "" || p ~ /(^|\/)node_modules\//) next
      d = dirname_of(p)
      while (d != "." && !(d in dirs)) {
        dirs[d] = 1
        d = dirname_of(d)
      }
      in_scope = (p ~ /^crates\/.*\.(rs|swift)$/ || p ~ /^extension\/src\/.*\.ts$/ || p ~ /^site\/src\/.*\.tsx?$/)
      if (!in_scope) next
      if (p ~ /(^|\/)(vendor|vendored|third_party|target|dist|build|\.build|out|generated|__generated__|gen|fixtures?|Pods|DerivedData)\// || p ~ /\.d\.ts$/ || p ~ /\.(generated|gen|g|pb)\.(rs|tsx?|swift)$/ || p ~ /_generated\.rs$/) next
      if (p ~ /(^|\/)(tests?|benches|e2e|__tests__)\// || p ~ /(^|\/)[^\/]*Tests\// || p ~ /(^|\/)tests?\.rs$/ || p ~ /_tests?\.rs$/ || p ~ /\.(test|spec)\.tsx?$/ || p ~ /Tests\.swift$/) next

      folder = dirname_of(p)
      name = basename_of(p)
      folder_count[folder]++

      if (name ~ /\.rs$/) {
        if (folder ~ /(^|\/)(examples|benches|bin)$/) next
        stem = substr(name, 1, length(name) - 3)
        has_stem[folder SUBSEP "rs" SUBSEP stem] = 1
        at = index(stem, "_")
        if (at > 1 && at < length(stem)) {
          prefix = substr(stem, 1, at - 1)
          members[folder SUBSEP "rs" SUBSEP prefix]++
        }
      } else if (name ~ /\.tsx?$/) {
        stem = name
        sub(/\.tsx?$/, "", stem)
        has_stem[folder SUBSEP "ts" SUBSEP stem] = 1
        i_dash = index(stem, "-")
        i_und = index(stem, "_")
        at = (i_dash > 0 && (i_und == 0 || i_dash < i_und)) ? i_dash : i_und
        if (at > 1 && at < length(stem)) {
          prefix = substr(stem, 1, at - 1)
          members[folder SUBSEP "ts" SUBSEP prefix]++
        }
      }
    }
    END {
      for (folder in folder_count) {
        c = folder_count[folder]
        if (c > fsoft) {
          printf "folder %s %d %s\n", folder, c, (c > fhard ? "hard" : "soft")
        }
      }
      for (k in members) {
        split(k, parts, SUBSEP)
        folder = parts[1]; lang = parts[2]; prefix = parts[3]
        c = members[k]
        base = (folder == "." ? prefix : folder "/" prefix)
        anchored = ((base in dirs) || ((folder SUBSEP lang SUBSEP prefix) in has_stem))
        need = anchored ? 2 : 3
        if (c >= need) {
          sep = (lang == "rs" ? "_" : "-")
          printf "family %s%s* %d %s\n", base, sep, c, base
        }
      }
    }'
}

rows=$(measure)
ceil_of() { [ -f "$EXC" ] && awk -v p="$1" '$1 == p { print $2; exit }' "$EXC" || true; }
folder_allowed() {
  local key="$1" count="$2"
  [ -f "$FOLDER_EXC" ] || return 1
  awk -v k="$key" -v c="$count" '
    { sub(/#.*/, ""); if (NF == 0) next; p = $1; sub(/\/$/, "", p); sub(/[-_]?\*$/, "", p)
      if (p == k) { if (NF < 2 || c <= $2) { found = 1; exit } }
    }
    END { exit (found ? 0 : 1) }' "$FOLDER_EXC"
}

errors=0 warns=0 oversoft=0 overhard=0 families=0 overfolders=0
out=$(mktemp); trap 'rm -f "$out"' EXIT
ann() { [ "${GITHUB_ACTIONS:-}" = true ] && echo "::$1 file=$2::$3" || true; }

while read -r p prod test maxtest; do
  [ -n "$p" ] || continue
  if [ "$prod" -eq 0 ] && [ "$test" -gt 0 ] && [ "$maxtest" -eq "$test" ] && [ "$test" -gt "$TESTCAP" ]; then
    # test-only file
    warns=$((warns + 1))
    printf '%6d  %-6s %s\n' "$test" "tests" "$p" >> "$out"
    ann warning "$p" "test file has $test lines (limit $TESTCAP)"
    continue
  fi
  if [ "$maxtest" -gt "$TESTCAP" ]; then
    warns=$((warns + 1))
    printf '%6d  %-6s %s\n' "$maxtest" "tests" "$p" >> "$out"
    ann warning "$p" "inline test module has $maxtest lines (limit $TESTCAP)"
  fi
  [ "$prod" -gt "$SOFT" ] || continue
  oversoft=$((oversoft + 1))
  if [ "$prod" -gt "$HARD" ]; then
    overhard=$((overhard + 1))
    limit=$(ceil_of "$p"); limit=${limit:-$HARD}
    if [ "$prod" -gt "$limit" ]; then
      errors=$((errors + 1))
      printf '%6d  %-6s %s (limit %d)\n' "$prod" "ERROR" "$p" "$limit" >> "$out"
      ann error "$p" "$prod non-test lines, limit $limit; split a module out before adding more"
    else
      warns=$((warns + 1))
      printf '%6d  %-6s %s (exception, ceiling %d)\n' "$prod" "warn" "$p" "$limit" >> "$out"
      ann warning "$p" "$prod non-test lines (exception ceiling $limit, soft limit $SOFT)"
    fi
  else
    warns=$((warns + 1))
    printf '%6d  %-6s %s\n' "$prod" "warn" "$p" >> "$out"
    ann warning "$p" "$prod non-test lines (soft limit $SOFT)"
  fi
done <<< "$rows"

shape_rows=$(check_shape)
if [ -n "$shape_rows" ]; then
  while read -r kind target count extra; do
    [ -n "$kind" ] || continue
    if [ "$kind" = "family" ]; then
      if folder_allowed "$extra" "$count"; then
        continue
      fi
      families=$((families + 1))
      errors=$((errors + 1))
      printf '%6d  %-6s %s (prefix family; move into a folder)\n' "$count" "ERROR" "$target" >> "$out"
      ann error "$target" "prefix family with $count files; move into a folder"
    elif [ "$kind" = "folder" ]; then
      overfolders=$((overfolders + 1))
      if [ "$extra" = "hard" ]; then
        if folder_allowed "$target" "$count"; then
          continue
        fi
        errors=$((errors + 1))
        printf '%6d  %-6s %s (folder limit %d)\n' "$count" "ERROR" "$target" "$FOLDER_HARD" >> "$out"
        ann error "$target" "folder has $count non-test sources (limit $FOLDER_HARD)"
      else
        warns=$((warns + 1))
        printf '%6d  %-6s %s (folder soft limit %d)\n' "$count" "warn" "$target" "$FOLDER_SOFT" >> "$out"
        ann warning "$target" "folder has $count non-test sources (soft limit $FOLDER_SOFT)"
      fi
    fi
  done <<< "$shape_rows"
fi

sort -rn "$out"
echo "over $SOFT: $oversoft, over $HARD: $overhard, prefix families: $families, wide folders: $overfolders, errors: $errors, warnings: $warns"

if [ "$update" -eq 1 ]; then
  tmp=$(mktemp)
  {
    echo "# <path> <ceiling>: non-test line ceilings for files above $HARD. Ceilings only go down."
    echo "# Refresh with scripts/file-size.sh --update-exceptions."
    while read -r p prod _ _; do
      [ -n "$p" ] || continue
      [ "$prod" -gt "$HARD" ] || continue
      old=$(ceil_of "$p")
      if [ -z "$old" ]; then
        if [ "$raise" -eq 1 ]; then echo "$p $prod"; else echo "not listing new oversized file $p ($prod); use --allow-raise" >&2; fi
      elif [ "$prod" -gt "$old" ] && [ "$raise" -eq 0 ]; then
        echo "$p $old"
      else
        echo "$p $prod"
      fi
    done <<< "$rows" | sort
  } > "$tmp"
  mv "$tmp" "$EXC"
  echo "wrote $EXC ($(grep -vc '^#' "$EXC") entries)"
  exit 0
fi

[ "$warn_only" -eq 1 ] && exit 0
[ "$errors" -eq 0 ]
