# DevSecOps Guardian Scan Report

**Scan ID:** a1b2c3d4
**Timestamp:** 2026-06-25T10:30:00+00:00
**Duration:** 2.45s
**Files Scanned:** 3
**Commit Blocked:** Yes

## Summary

- **CRITICAL:** 3
- **HIGH:** 1

## Findings

### 1. AWS Access Key

| Field | Value |
|-------|-------|
| **File** | `auth/login.py` |
| **Line** | 1 |
| **Severity** | CRITICAL |
| **Category** | Secret Detection |
| **Scanner** | regex |
| **Confidence** | 97% |

**Why:** Potential AWS Access Key detected in code.

**Code:**
```
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
```

**Recommended Fix:** Remove the secret and use environment variables or a secrets manager.

*Validated by LLM (confidence: 97%)*

---

### 2. SQL Injection

| Field | Value |
|-------|-------|
| **File** | `auth/login.py` |
| **Line** | 5 |
| **Severity** | CRITICAL |
| **Category** | Security Vulnerability |
| **Scanner** | owasp_rules |
| **Confidence** | 95% |

**Why:** User input directly concatenated into SQL query.

**Code:**
```
query = "SELECT * FROM users WHERE username='" + username + "'"
```

**Recommended Fix:**
```python
query = "SELECT * FROM users WHERE username=%s"
cursor.execute(query, (username,))
```

*Validated by LLM (confidence: 95%)*

---

### 3. Email Address (PII)

| Field | Value |
|-------|-------|
| **File** | `auth/login.py` |
| **Line** | 8 |
| **Severity** | CRITICAL |
| **Category** | PII Detection |

**Why:** Potential Email Address found in source code.

**Recommended Fix:** Remove PII from code. Use tokenization or secure storage.

---

### 4. Restricted Client Reference

| Field | Value |
|-------|-------|
| **File** | `config/settings.yaml` |
| **Line** | 12 |
| **Severity** | HIGH |
| **Category** | Client Confidential Information |

**Why:** Restricted client reference 'ClientABC' detected.

**Recommended Fix:** Remove client-specific references or use configuration outside version control.
