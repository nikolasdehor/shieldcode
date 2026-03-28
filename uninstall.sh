#!/usr/bin/env bash
set -e

SKILL_DIR="$HOME/.claude/skills/shieldcode"

if [ -d "$SKILL_DIR" ]; then
  rm -rf "$SKILL_DIR"
  echo "ShieldCode uninstalled."
else
  echo "ShieldCode is not installed."
fi
