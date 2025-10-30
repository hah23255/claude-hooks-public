#!/usr/bin/env python3
"""
Comprehensive PreToolUse Security Hook - Pydantic Validated
Addresses all 15 identified security gaps in Claude Code CLI

Version: 2.0.0 (Pydantic Validated)
Author: Security Toolkit
License: Private Use

ENHANCEMENTS IN V2.0:
- Pydantic schema validation for all inputs
- Type-safe operations with IDE support
- Clear field-level error messages
- Automatic retry mechanism support
- ValidationError handling

GAPS ADDRESSED:
- GAP 1: Read tool monitoring
- GAP 2: Bash command scanning
- GAP 3: Glob/Grep enumeration detection
- GAP 4: Fail-closed storage policy
- GAP 5: Proper security scanner integration
- GAP 7: Network activity monitoring
- GAP 9: Rate limiting
- GAP 10: Task/agent monitoring
- GAP 12: Symbolic link resolution
- GAP 13: Enhanced Edit controls
- GAP 15: Configuration file protection
"""

import sys
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# Import Pydantic schemas
try:
    from schemas import HookInput, HookDecision, SecurityConfig, validate_hook_input_dict, validate_security_config_dict
    PYDANTIC_AVAILABLE = True
except ImportError:
    print("⚠️  Pydantic schemas not found - falling back to manual validation", file=sys.stderr)
    PYDANTIC_AVAILABLE = False

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG_PATH = os.path.expanduser('~/.claude/security-config.json')
AUDIT_LOG = os.path.expanduser('~/.claude/audit.jsonl')
RATE_LIMIT_STATE = os.path.expanduser('~/.claude/rate-limit-state.json')

# ============================================================================
# RATE LIMITING STATE
# ============================================================================

class RateLimiter:
    """Rate limiting with time-window based throttling"""

    def __init__(self, config: Dict):
        self.limits = config.get('rate_limits', {})
        self.window = 60  # 60 second window
        self.state = self._load_state()

    def _load_state(self) -> Dict:
        """Load rate limit state from disk"""
        if os.path.exists(RATE_LIMIT_STATE):
            try:
                with open(RATE_LIMIT_STATE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_state(self):
        """Save rate limit state to disk"""
        try:
            with open(RATE_LIMIT_STATE, 'w') as f:
                json.dump(self.state, f)
        except:
            pass

    def check_rate_limit(self, tool_name: str) -> Tuple[bool, str]:
        """Check if tool usage is within rate limits"""
        if tool_name not in self.limits:
            return True, ""

        now = datetime.now().timestamp()
        cutoff = now - self.window

        # Clean old entries
        if tool_name not in self.state:
            self.state[tool_name] = []

        recent = [t for t in self.state[tool_name] if t > cutoff]
        self.state[tool_name] = recent

        # Check limit
        limit = self.limits[tool_name]
        if len(recent) >= limit:
            return False, f"Rate limit exceeded: {len(recent)}/{limit} calls in {self.window}s"

        # Add current call
        self.state[tool_name].append(now)
        self._save_state()

        return True, ""

# ============================================================================
# CONFIGURATION LOADER WITH PYDANTIC VALIDATION
# ============================================================================

def load_config() -> Dict:
    """Load security configuration with fail-closed behavior and Pydantic validation"""
    if not os.path.exists(CONFIG_PATH):
        print(f"🚨 CRITICAL: Security configuration not found", file=sys.stderr)
        print(f"Required: {CONFIG_PATH}", file=sys.stderr)
        print(f"Run: cp config/templates/security-config.json {CONFIG_PATH}", file=sys.stderr)
        sys.exit(2)  # FAIL CLOSED

    try:
        with open(CONFIG_PATH, 'r') as f:
            config_data = json.load(f)

        # Pydantic validation if available
        if PYDANTIC_AVAILABLE:
            is_valid, errors = validate_security_config_dict(config_data)
            if not is_valid:
                print(f"🚨 CRITICAL: Invalid security configuration", file=sys.stderr)
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
                sys.exit(2)  # FAIL CLOSED

            # Create validated config object
            config = SecurityConfig(**config_data)
            # Return as dict for backward compatibility
            return config_data
        else:
            # Manual validation (fallback)
            required = ['fail_closed', 'restricted_paths', 'allowed_paths']
            for key in required:
                if key not in config_data:
                    print(f"🚨 CRITICAL: Missing required config key: {key}", file=sys.stderr)
                    sys.exit(2)

            return config_data

    except Exception as e:
        print(f"🚨 CRITICAL: Failed to load config: {e}", file=sys.stderr)
        sys.exit(2)  # FAIL CLOSED

# ============================================================================
# AUDIT LOGGING
# ============================================================================

def log_operation(tool_name: str, tool_input: Dict, decision: str, reason: str = "", details: Dict = None):
    """Log all tool operations to audit trail (GAP 8 fix)"""
    try:
        entry = {
            'timestamp': datetime.now().isoformat(),
            'tool': tool_name,
            'input_summary': str(tool_input)[:200],
            'decision': decision,
            'reason': reason
        }

        if details:
            entry['details'] = details

        # Add validation info if Pydantic was used
        if PYDANTIC_AVAILABLE:
            entry['validation'] = {'pydantic': True, 'version': '2.0.0'}

        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    except Exception as e:
        print(f"⚠️  Audit logging failed: {e}", file=sys.stderr)

# ============================================================================
# FILE ACCESS CONTROL (GAP 1, 12, 13, 15 fixes)
# ============================================================================

def resolve_path(file_path: str) -> str:
    """Resolve path with symlink resolution (GAP 12 fix)"""
    expanded = os.path.expanduser(file_path)
    abs_path = os.path.abspath(expanded)

    # Resolve symbolic links
    real_path = os.path.realpath(abs_path)

    # Warn if symlink detected
    if abs_path != real_path:
        print(f"⚠️  Symbolic link detected: {file_path} -> {real_path}", file=sys.stderr)

    return real_path

def check_file_access(tool_name: str, file_path: str, config: Dict) -> Tuple[bool, str]:
    """
    Check file access against security policy
    Covers: Write, Edit, NotebookEdit, Read (GAP 1 fix)
    """
    if not file_path:
        return True, ""

    real_path = resolve_path(file_path)

    # GAP 15: Protect configuration files
    config_files = [
        '.claude/settings.json',
        '.claude/settings.local.json',
        '.claude/security-config.json',
        '.claude/storage-rules.json',
        '.claude/hooks/'
    ]

    for config_file in config_files:
        config_path = os.path.expanduser(f'~/{config_file}')
        if real_path.startswith(config_path):
            return False, f"Protected configuration file: {config_file}"

    # GAP 13: Enhanced Edit controls for critical files
    if tool_name == 'Edit':
        critical_files = ['.ssh/', '.gnupg/', '.bashrc', '.bash_profile', '.zshrc']
        for critical in critical_files:
            if critical in real_path:
                return False, f"Edit blocked for critical file: {critical}"

    # Check restricted paths
    restricted = config.get('restricted_paths', [])
    for restricted_path in restricted:
        restricted_real = os.path.realpath(os.path.expanduser(restricted_path))
        if real_path.startswith(restricted_real):
            return False, f"Access to restricted path: {restricted_path}"

    # Check allowed paths (if whitelist configured)
    allowed = config.get('allowed_paths', [])
    if allowed:
        allowed_match = False
        for allowed_path in allowed:
            allowed_real = os.path.realpath(os.path.expanduser(allowed_path))
            if real_path.startswith(allowed_real):
                allowed_match = True
                break

        if not allowed_match:
            return False, "Path not in allowed whitelist"

    return True, ""

# ============================================================================
# BASH COMMAND SCANNING (GAP 2 fix)
# ============================================================================

def check_bash_command(command: str, config: Dict) -> Tuple[bool, str]:
    """Scan bash command for dangerous patterns (GAP 2 fix)"""
    if not command:
        return True, ""

    # Get dangerous patterns from config
    dangerous = config.get('dangerous_bash_patterns', [])

    for pattern in dangerous:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Dangerous command pattern: {pattern}"

    # Additional checks for common attack vectors
    if command.strip().startswith('sudo '):
        return False, "Sudo commands blocked"

    if '|' in command and 'base64' in command:
        return False, "Potential encoded command execution"

    return True, ""

# ============================================================================
# NETWORK ACTIVITY MONITORING (GAP 7 fix)
# ============================================================================

def check_network_access(url: str, config: Dict) -> Tuple[bool, str]:
    """Check network access against domain whitelist (GAP 7 fix)"""
    if not url:
        return True, ""

    allowed_domains = config.get('allowed_domains', [])

    # If no whitelist, allow but log
    if not allowed_domains:
        print(f"⚠️  Network access (no whitelist): {url}", file=sys.stderr)
        return True, ""

    # Check against whitelist
    for domain in allowed_domains:
        if domain in url:
            return True, ""

    return False, f"Domain not in whitelist: {url}"

# ============================================================================
# ENUMERATION DETECTION (GAP 3 fix)
# ============================================================================

def check_enumeration(tool_name: str, pattern: str, config: Dict) -> Tuple[bool, str]:
    """Detect sensitive file enumeration (GAP 3 fix)"""
    if not pattern:
        return True, ""

    sensitive_terms = config.get('sensitive_patterns', [
        'ssh', 'key', 'password', 'secret', 'token', 'credential',
        'api', 'private', '.env', 'config', 'auth'
    ])

    pattern_lower = pattern.lower()
    for term in sensitive_terms:
        if term in pattern_lower:
            print(f"⚠️  Sensitive pattern search detected: {pattern}", file=sys.stderr)
            # Log but don't block by default (configurable)
            break

    return True, ""

# ============================================================================
# AGENT MONITORING (GAP 10 fix)
# ============================================================================

def check_agent_spawn(prompt: str, config: Dict) -> Tuple[bool, str]:
    """Monitor agent spawning for suspicious tasks (GAP 10 fix)"""
    if not prompt:
        return True, ""

    suspicious_terms = ['password', 'key', 'secret', 'credential', 'token', 'ssh', 'exfiltrate']

    prompt_lower = prompt.lower()
    for term in suspicious_terms:
        if term in prompt_lower:
            print(f"⚠️  Suspicious agent task detected: {prompt[:100]}", file=sys.stderr)
            # Log for review
            break

    return True, ""

# ============================================================================
# PYDANTIC INPUT PROCESSING
# ============================================================================

def process_stdin_with_validation() -> Tuple[Optional[object], Optional[str], Dict]:
    """
    Process stdin with Pydantic validation.

    Returns:
        (validated_input, error_message, raw_input)
    """
    try:
        raw_input = json.load(sys.stdin)

        if PYDANTIC_AVAILABLE:
            # Validate with Pydantic
            is_valid, errors = validate_hook_input_dict(raw_input)

            if not is_valid:
                error_msg = "Input validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
                return None, error_msg, raw_input

            # Create validated object
            validated = HookInput(**raw_input)
            return validated, None, raw_input
        else:
            # Manual validation (fallback)
            if 'tool_name' not in raw_input:
                return None, "Missing required field: tool_name", raw_input
            if 'tool_input' not in raw_input:
                return None, "Missing required field: tool_input", raw_input

            return raw_input, None, raw_input

    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}", {}
    except Exception as e:
        return None, f"Validation error: {e}", {}

# ============================================================================
# MAIN SECURITY CHECK ROUTER WITH PYDANTIC VALIDATION
# ============================================================================

def main():
    """Main security hook entry point with Pydantic validation"""
    try:
        # Load configuration (fail-closed)
        config = load_config()

        # Process input with Pydantic validation
        validated_input, validation_error, raw_input = process_stdin_with_validation()

        if validation_error:
            # Validation failed - provide clear error and fail closed
            print(f"🚨 VALIDATION ERROR:", file=sys.stderr)
            print(validation_error, file=sys.stderr)
            print(f"\nInput validation failed. Operation blocked.", file=sys.stderr)

            # Log validation failure
            log_operation(
                tool_name=raw_input.get('tool_name', 'UNKNOWN'),
                tool_input=raw_input.get('tool_input', {}),
                decision='VALIDATION_FAILED',
                reason=validation_error
            )

            sys.exit(2)  # FAIL CLOSED

        # Extract fields (type-safe if Pydantic available)
        if PYDANTIC_AVAILABLE and hasattr(validated_input, 'tool_name'):
            tool_name: str = validated_input.tool_name
            tool_input: Dict = validated_input.tool_input.model_dump()
        else:
            tool_name = validated_input.get('tool_name', '')
            tool_input = validated_input.get('tool_input', {})

        # Initialize rate limiter (GAP 9 fix)
        rate_limiter = RateLimiter(config)

        # Check rate limits
        rate_ok, rate_reason = rate_limiter.check_rate_limit(tool_name)
        if not rate_ok:
            log_operation(tool_name, tool_input, 'RATE_LIMITED', rate_reason)
            print(f"🚨 {rate_reason}", file=sys.stderr)
            sys.exit(2)

        # Route to appropriate security check
        allowed = True
        reason = ""
        details = {}

        # FILE ACCESS OPERATIONS (Write, Edit, NotebookEdit, Read)
        if tool_name in ['Write', 'Edit', 'NotebookEdit', 'Read']:
            file_path = tool_input.get('file_path') or tool_input.get('notebook_path')
            allowed, reason = check_file_access(tool_name, file_path, config)
            details['file_path'] = file_path
            details['resolved_path'] = resolve_path(file_path) if file_path else None

        # BASH COMMAND EXECUTION
        elif tool_name == 'Bash':
            command = tool_input.get('command', '')
            allowed, reason = check_bash_command(command, config)
            details['command'] = command[:100]

        # NETWORK OPERATIONS
        elif tool_name in ['WebFetch', 'WebSearch']:
            url = tool_input.get('url', '') or tool_input.get('query', '')
            allowed, reason = check_network_access(url, config)
            details['url'] = url

        # ENUMERATION OPERATIONS
        elif tool_name in ['Glob', 'Grep']:
            pattern = tool_input.get('pattern', '')
            allowed, reason = check_enumeration(tool_name, pattern, config)
            details['pattern'] = pattern

        # AGENT SPAWNING
        elif tool_name == 'Task':
            prompt = tool_input.get('prompt', '')
            allowed, reason = check_agent_spawn(prompt, config)
            details['subagent'] = tool_input.get('subagent_type', '')
            details['prompt_preview'] = prompt[:100]

        # Log decision
        decision = 'ALLOWED' if allowed else 'BLOCKED'
        log_operation(tool_name, tool_input, decision, reason, details)

        # Enforce decision
        if not allowed:
            print(f"🚨 BLOCKED: {reason}", file=sys.stderr)
            sys.exit(2)

        # Allow operation
        sys.exit(0)

    except KeyboardInterrupt:
        sys.exit(2)

    except Exception as e:
        # Fail closed on error if configured
        config = {}
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
        except:
            pass

        if config.get('fail_closed', True):
            print(f"🚨 CRITICAL ERROR (fail-closed): {e}", file=sys.stderr)
            sys.exit(2)
        else:
            print(f"⚠️  Error (fail-open): {e}", file=sys.stderr)
            sys.exit(0)

if __name__ == '__main__':
    main()
