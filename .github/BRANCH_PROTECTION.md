# =============================================================================
# Branch Protection Configuration Guide
# =============================================================================
# This document describes the recommended branch protection settings
# for integrating DevSecOps Gate with your repository.
#
# Apply these settings in GitHub: Settings → Branches → Branch protection rules
# =============================================================================

# Recommended Branch Protection Rules for `main` branch
# ======================================================

## Required Settings:

### 1. Require status checks to pass before merging
# Enable this and add:
# - "🔍 Security Scan" (from security-gate.yml workflow)
# - "🚦 Gate Summary" (optional, for better visibility)

### 2. Require branches to be up to date before merging
# Ensures security scan runs on latest code

### 3. Require pull request reviews before merging
# - Required approving reviews: 1 (minimum)
# - Dismiss stale PR approvals when new commits are pushed: ✅
# - Require review from Code Owners: (optional)

### 4. Restrict who can push to matching branches
# - Only allow merges via pull request

## GitHub CLI Commands to Set Up Protection:

```bash
# Set up branch protection for main branch
gh api repos/{owner}/{repo}/branches/main/protection -X PUT \
  -H "Accept: application/vnd.github+json" \
  -f required_status_checks='{"strict":true,"contexts":["🔍 Security Scan","🚦 Gate Summary"]}' \
  -f enforce_admins=false \
  -f required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true}' \
  -f restrictions=null
```

## YAML Configuration Reference:

```yaml
# .github/branch-protection.yml (for automation tools)
branches:
  - name: main
    protection:
      required_status_checks:
        strict: true
        contexts:
          - "🔍 Security Scan"
          - "🚦 Gate Summary"
      required_pull_request_reviews:
        required_approving_review_count: 1
        dismiss_stale_reviews: true
        require_code_owner_reviews: false
      enforce_admins: false
      restrictions: null
      
  - name: develop
    protection:
      required_status_checks:
        strict: false  # Less strict for develop
        contexts:
          - "🔍 Security Scan"
      required_pull_request_reviews:
        required_approving_review_count: 1
```

# =============================================================================
# Security Gate Behavior by Branch
# =============================================================================

## Main Branch:
# - Full security scan required
# - Gate MUST pass (no critical/high violations)
# - PR review required
# - No direct pushes allowed

## Develop Branch:
# - Security scan required
# - Gate should pass (warnings allowed)
# - PR review recommended
# - No direct pushes (recommended)

## Feature Branches:
# - Security scan runs on PR
# - Informational only (can be configured)
# - Helps developers catch issues early

# =============================================================================
# Recommended Workflow
# =============================================================================

# 1. Developer creates feature branch
# 2. Developer pushes code → Security scan runs (informational)
# 3. Developer opens PR to main/develop
# 4. Security Gate runs full scan
#    - PASSED: PR can be merged after review
#    - WARNING: PR can be merged with caution
#    - FAILED: PR blocked until issues fixed
# 5. Reviewer approves PR
# 6. PR merged → Production deployment can proceed

# =============================================================================
# Emergency Override Procedure
# =============================================================================

# In case of emergency where security gate needs to be bypassed:
#
# 1. Repository admin can temporarily disable required status checks
# 2. Document the reason in the PR description
# 3. Create a follow-up issue to address security findings
# 4. Re-enable protection immediately after merge
#
# ⚠️ CAUTION: This should be extremely rare and well-documented!
