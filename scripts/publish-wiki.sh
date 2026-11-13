#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# publish-wiki.sh: publish the repo's wiki/ folder to the GitHub wiki (a separate git repo,
# mlaify/openlens-fw.wiki.git). The user documentation moved to docs.mlaify.io/openlens-fw (source:
# mlaify/docs, content/openlens-fw/) on 2026-11-13; wiki/ now holds pages that point there, so old
# wiki links keep working. The wiki/ folder is the source of those pages: they go through PRs like
# any doc, and this script mirrors them, so edits made on the wiki's web page are overwritten.
# WIKI_REMOTE=<url> publishes somewhere else (a fork's or a mirror's wiki).
# Owner's terminal, from an up-to-date main:
#
#   bash scripts/publish-wiki.sh
#
# It clones the wiki, replaces its pages with wiki/*.md (a page removed from wiki/ is removed from
# the wiki), shows the change, and pushes only after you answer y.
# The wiki repo has to exist first: GitHub creates it only when its first page exists. For a new
# wiki, open the repo's Wiki tab, "Create the first page", save it as is, then run this.
set -euo pipefail
cd "$(dirname "$0")/.."
REMOTE=${WIKI_REMOTE:-git@github.com:mlaify/openlens-fw.wiki.git}

[ "$(git branch --show-current)" = main ] || { echo "run this on main"; exit 1; }
[ -z "$(git status --porcelain -- wiki)" ] || { echo "wiki/ has uncommitted changes"; exit 1; }
ls wiki/*.md >/dev/null 2>&1 || { echo "no pages in wiki/"; exit 1; }
rev=$(git rev-parse --short HEAD)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if ! git clone -q --depth 1 "$REMOTE" "$tmp/wiki"; then
	echo "clone failed: check $REMOTE, or create the wiki's first page first (see the top of this script)"
	exit 1
fi
find "$tmp/wiki" -maxdepth 1 -name '*.md' -delete
cp wiki/*.md "$tmp/wiki/"
cd "$tmp/wiki"
git add -A
if git diff --cached --quiet; then
	echo "the wiki is already up to date with $rev"
	exit 0
fi
git diff --cached --stat
read -r -p "Push these changes to the wiki? [y/N] " answer
[ "$answer" = y ] || { echo "nothing pushed"; exit 1; }
git commit -q -m "Publish wiki/ from openlens-fw $rev"
git push -q origin HEAD
echo "published wiki/ from $rev"
