#!/bin/bash
# Test script for V1 (Basic) security hook

echo "========================================"
echo "Testing V1 (Basic) Security Hook"
echo "========================================"
echo ""

# Test 1: Valid Read operation
echo "Test 1: Valid Read operation"
echo '{
  "session_id": "test-001",
  "transcript_path": "/tmp/transcript.json",
  "cwd": "/tmp",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Read",
  "tool_input": {
    "file_path": "/storage/emulated/0/Enterprise/test.txt"
  }
}' | python3 ../v1-basic/security_hook.py 2>&1

if [ $? -eq 0 ]; then
  echo "✅ Test 1 PASSED: Valid Read allowed"
else
  echo "❌ Test 1 FAILED: Valid Read blocked"
fi
echo ""

# Test 2: Protected config file (should block)
echo "Test 2: Protected config file write (should block)"
echo '{
  "session_id": "test-002",
  "transcript_path": "/tmp/transcript.json",
  "cwd": "/tmp",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/data/data/com.termux/files/home/.claude/settings.json",
    "content": "malicious"
  }
}' | python3 ../v1-basic/security_hook.py 2>&1

if [ $? -eq 2 ]; then
  echo "✅ Test 2 PASSED: Protected file blocked"
else
  echo "❌ Test 2 FAILED: Protected file not blocked"
fi
echo ""

# Test 3: Dangerous bash command (should block)
echo "Test 3: Dangerous bash command (should block)"
echo '{
  "session_id": "test-003",
  "transcript_path": "/tmp/transcript.json",
  "cwd": "/tmp",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf /"
  }
}' | python3 ../v1-basic/security_hook.py 2>&1

if [ $? -eq 2 ]; then
  echo "✅ Test 3 PASSED: Dangerous command blocked"
else
  echo "❌ Test 3 FAILED: Dangerous command not blocked"
fi
echo ""

echo "========================================"
echo "V1 Testing Complete"
echo "========================================"
