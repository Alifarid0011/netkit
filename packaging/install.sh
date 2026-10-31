#!/bin/sh
set -eu
prefix="${HOME}/.local"
force=false
while [ "$#" -gt 0 ]; do
 case "$1" in
 --prefix) [ "$#" -ge 2 ] || { echo '--prefix needs a path' >&2; exit 2; }; prefix="$2"; shift 2;;
 --force) force=true; shift;;
 -h|--help) echo 'Usage: ./install.sh [--prefix PATH] [--force]'; exit 0;;
 *) echo "Unknown argument: $1" >&2; exit 2;;
 esac
done
[ "$(uname -s)" = Linux ] || { echo 'Linux is required' >&2; exit 1; }
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -x "$base/netkit" ] || { echo 'Run the installer from an extracted release archive' >&2; exit 1; }
[ -n "$prefix" ] || { echo 'Prefix cannot be empty' >&2; exit 2; }
mkdir -p "$prefix/bin"
target="$prefix/bin/netkit"
if [ -e "$target" ] || [ -L "$target" ]; then
 [ "$force" = true ] || { echo "Already exists: $target (use --force to replace)" >&2; exit 1; }
fi
# Stage on the same filesystem, then rename; do not follow an existing binary symlink.
staging=$(mktemp "$prefix/bin/.netkit.XXXXXX")
trap 'rm -f "$staging"' EXIT HUP INT TERM
cp "$base/netkit" "$staging"
chmod 755 "$staging"
if [ "$force" = true ]; then
 mv -fT "$staging" "$target"
else
 # Hard-link creation fails atomically if a destination appeared meanwhile.
 ln "$staging" "$target"
 rm -f "$staging"
fi
printf 'Installed %s\nEnsure %s/bin is on PATH.\n' "$target" "$prefix"
