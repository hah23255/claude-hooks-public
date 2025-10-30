# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2025-10-30

### Added - Version 2 (Pydantic)

**New Pydantic-Validated Hook**:
- Pydantic v2 schema validation for all hook inputs
- Type-safe operations with full IDE autocomplete support
- Clear field-level error messages on validation failures
- Automatic validation before security checks
- Graceful fallback to manual validation if Pydantic unavailable
- Enhanced audit logging with validation metadata
- Backward compatible with v1.0.0

**Security Enhancements**:
- Path traversal detection via Pydantic validators
- Tool name whitelist enforcement
- Missing field detection with clear error messages
- Invalid permission mode rejection
- Empty field detection
- Rate limit validation (ensures positive integers)

**Developer Experience**:
- Type hints throughout for better IDE support
- Comprehensive validation test suite
- Detailed usage guide (SCHEMAS_USAGE.md)
- Migration documentation

### Version 1 (Basic) - Maintained

All features from v1.0.0 remain available:
- Manual JSON parsing (no external dependencies)
- 15 security gaps addressed
- Fail-closed by default
- Comprehensive audit logging
- Rate limiting (60-second window)
- File access controls
- Bash command scanning
- Network activity monitoring
- Symbolic link resolution
- Protected configuration file blocking

## [1.0.0] - 2025-10-29

### Initial Release

**Core Features**:
- Comprehensive security hook for Claude Code CLI
- Manual JSON validation (dependency-free)
- Fail-closed security model
- Audit logging to JSONL

**Security Controls**:
- File access controls (GAP 1, 12, 13, 15)
- Bash command scanning (GAP 2)
- Glob/Grep enumeration detection (GAP 3)
- Fail-closed storage policy (GAP 4)
- Security scanner integration (GAP 5)
- Network activity monitoring (GAP 7)
- Rate limiting (GAP 9)
- Task/agent monitoring (GAP 10)
- Symbolic link resolution (GAP 12)
- Enhanced Edit controls (GAP 13)
- Configuration file protection (GAP 15)

**Configuration**:
- security-config.json with comprehensive settings
- Configurable rate limits per tool
- Path-based access control (whitelist/blacklist)
- Dangerous bash pattern detection
- Domain whitelist for network access

**Testing**:
- Production-tested on Termux/Android
- Linux compatible
- Verified fail-closed behavior

---

## Version Comparison

| Feature | V1 (Basic) | V2 (Pydantic) |
|---------|------------|---------------|
| Dependencies | None | Pydantic v2 |
| Validation | Manual | Schema-based |
| Type Safety | No | Yes (full) |
| Error Messages | Generic | Field-level |
| IDE Support | Limited | Full autocomplete |
| Performance | Fast | ~1ms overhead |
| Fallback | N/A | Graceful to V1 |
| Recommended For | Learning, minimal deps | Production |

---

## Migration Guide

### From V1 to V2

1. Install Pydantic:
   ```bash
   pip install pydantic
   ```

2. Copy schemas.py to hooks directory:
   ```bash
   cp v2-pydantic/schemas.py ~/.claude/hooks/
   ```

3. Replace security hook:
   ```bash
   cp v2-pydantic/security_hook.py ~/.claude/hooks/comprehensive_pretooluse.py
   ```

4. Test:
   ```bash
   python3 tests/test_v2.sh
   ```

### Rollback to V1

Simply replace with V1 version:
```bash
cp v1-basic/security_hook.py ~/.claude/hooks/comprehensive_pretooluse.py
```

---

## Roadmap

### Planned for v2.1.0
- [ ] Automatic retry mechanism on validation failures
- [ ] Custom validator plugins
- [ ] Performance profiling tools
- [ ] Additional security checks

### Planned for v3.0.0
- [ ] Multi-hook orchestration
- [ ] Policy-as-code configuration
- [ ] Real-time monitoring dashboard
- [ ] Encrypted audit logs

---

**For detailed documentation, see README.md**
