#!/bin/bash
# Test script for V2 (Pydantic) security hook

echo "========================================"
echo "Testing V2 (Pydantic) Security Hook"
echo "========================================"
echo ""

# Check Pydantic availability
echo "Checking Pydantic installation..."
python3 -c "import pydantic; print(f'✅ Pydantic {pydantic.VERSION} installed')" 2>&1
if [ $? -ne 0 ]; then
  echo "⚠️  Pydantic not installed. Install with: pip install pydantic"
  exit 1
fi
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
}' | python3 ../v2-pydantic/security_hook.py 2>&1

if [ $? -eq 0 ]; then
  echo "✅ Test 1 PASSED: Valid Read allowed"
else
  echo "❌ Test 1 FAILED: Valid Read blocked"
fi
echo ""

# Test 2: Invalid tool name (Pydantic should catch)
echo "Test 2: Invalid tool name (Pydantic validation)"
echo '{
  "session_id": "test-002",
  "transcript_path": "/tmp/transcript.json",
  "cwd": "/tmp",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "HackerTool",
  "tool_input": {}
}' | python3 ../v2-pydantic/security_hook.py 2>&1

if [ $? -eq 2 ]; then
  echo "✅ Test 2 PASSED: Invalid tool name caught by Pydantic"
else
  echo "❌ Test 2 FAILED: Invalid tool name not caught"
fi
echo ""

# Test 3: Path traversal (Pydantic should catch)
echo "Test 3: Path traversal attack (Pydantic validation)"
echo '{
  "session_id": "test-003",
  "transcript_path": "/tmp/transcript.json",
  "cwd": "/tmp",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Read",
  "tool_input": {
    "file_path": "../../etc/passwd"
  }
}' | python3 ../v2-pydantic/security_hook.py 2>&1

if [ $? -eq 2 ]; then
  echo "✅ Test 3 PASSED: Path traversal caught by Pydantic"
else
  echo "❌ Test 3 FAILED: Path traversal not caught"
fi
echo ""

# Test 4: Protected config file (security check should block)
echo "Test 4: Protected config file write (security check)"
echo '{
  "session_id": "test-004",
  "transcript_path": "/tmp/transcript.json",
  "cwd": "/tmp",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/data/data/com.termux/files/home/.claude/settings.json",
    "content": "malicious"
  }
}' | python3 ../v2-pydantic/security_hook.py 2>&1

if [ $? -eq 2 ]; then
  echo "✅ Test 4 PASSED: Protected file blocked"
else
  echo "❌ Test 4 FAILED: Protected file not blocked"
fi
echo ""

# Test 5: Dangerous bash command (security check should block)
echo "Test 5: Dangerous bash command (security check)"
echo '{
  "session_id": "test-005",
  "transcript_path": "/tmp/transcript.json",
  "cwd": "/tmp",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf /"
  }
}' | python3 ../v2-pydantic/security_hook.py 2>&1

if [ $? -eq 2 ]; then
  echo "✅ Test 5 PASSED: Dangerous command blocked"
else
  echo "❌ Test 5 FAILED: Dangerous command not blocked"
fi
echo ""

echo "========================================"
echo "V2 Testing Complete"
echo "========================================"
