#!/usr/bin/env bash
set -e

SKILL_DIR="$HOME/.claude/skills/shieldcode"

echo "Installing ShieldCode skill..."
mkdir -p "$SKILL_DIR"
cp "$(dirname "$0")/skills/shieldcode/SKILL.md" "$SKILL_DIR/SKILL.md"
echo "ShieldCode installed to $SKILL_DIR"
echo "Claude will now automatically apply security hardening and error handling rules."
