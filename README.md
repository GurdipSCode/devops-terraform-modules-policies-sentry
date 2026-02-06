# devops-terraform-modules-policies-sentry

This repository contains Open Policy Agent (OPA) policies to enforce best practices and security requirements for the Sentry Terraform module.

## Overview

The policies validate:
- ✅ Organization configuration
- ✅ Team structure and naming
- ✅ Project configuration and assignments
- ✅ Issue alert settings
- ✅ Metric alert configuration
- ✅ Naming conventions
- ✅ Security best practices
- ✅ Resource limits

## Policy Categories

### 1. Organization Policies
- Validates organization slug format (lowercase, alphanumeric, hyphens only)
- Enforces organization name when creating new organizations
- Limits organization slug length to 50 characters

### 2. Team Policies
- **DENY**: Empty team names
- **DENY**: Team names exceeding 64 characters
- **WARN**: Team names not starting with capital letter
- **WARN**: Team keys not following snake_case convention
- **DENY**: At least one team must be defined

### 3. Project Policies
- **DENY**: Projects without team assignments
- **DENY**: Projects referencing non-existent teams
- **DENY**: Invalid platform names
- **WARN**: Projects without alerts configured
- **WARN**: Resolve age < 1 hour or > 30 days
- **WARN**: Projects assigned to > 5 teams

### 4. Issue Alert Policies
- **DENY**: Alerts referencing non-existent projects
- **DENY**: Invalid action_match or filter_match values
- **DENY**: Frequency < 5 minutes (alert fatigue)
- **DENY**: Frequency > 1 week (too infrequent)
- **WARN**: Alerts with no conditions or actions

### 5. Metric Alert Policies
- **DENY**: Invalid threshold_type (must be "above" or "below")
- **DENY**: Time window < 1 minute or > 24 hours
- **WARN**: Alerts with no triggers
- **WARN**: Alerts with > 3 triggers (too complex)

### 6. Naming Conventions
- **WARN**: All keys should follow snake_case convention
- Enforces consistent naming across teams, projects, and alerts

### 7. Security & Best Practices
- **WARN**: > 20 teams (maintainability concern)
- **WARN**: > 50 projects (consider splitting)
- **WARN**: > 100 alerts (alert fatigue)

## Valid Sentry Platforms

```
python, javascript, node, go, ruby, php, java, csharp, dotnet,
react, vue, angular, django, flask, express, other
```

## Installation

### Install OPA

**Windows:**
```powershell
winget install OpenPolicyAgent.OPA
```

**macOS:**
```bash
brew install opa
```

**Linux:**
```bash
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod 755 ./opa
sudo mv ./opa /usr/local/bin/
```

**Verify Installation:**
```bash
opa version
```

## Usage

### Test with Sample Input

```powershell
# Run validation
.\scripts\Test-OPAPolicies.ps1

# Pretty output (default)
.\scripts\Test-OPAPolicies.ps1 -Format pretty

# JSON output
.\scripts\Test-OPAPolicies.ps1 -Format json

# Table output
.\scripts\Test-OPAPolicies.ps1 -Format table

# Fail on warnings
.\scripts\Test-OPAPolicies.ps1 -FailOnWarnings
```

### Test with Custom Input

```powershell
.\scripts\Test-OPAPolicies.ps1 -InputFile "my-config.json"
```

### Generate Input from Terraform

```powershell
# Create a JSON file with your terraform.tfvars values
terraform show -json | jq '.values.root_module.child_modules[0].variables' > input.json

# Test against policies
.\scripts\Test-OPAPolicies.ps1 -InputFile input.json
```

## Example Output

```
═══════════════════════════════════════════════════════════════
         OPA POLICY VALIDATION RESULTS
═══════════════════════════════════════════════════════════════

📊 Summary:
   Total Denies:   0
   Total Warnings: 2

✅ No policy violations found!

⚠️  WARNINGS (BEST PRACTICES):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • Team 'backend' name should start with a capital letter: 'backend team'
  • Project 'web_app' key should follow snake_case naming convention

═══════════════════════════════════════════════════════════════
✅ Policy validation passed!
```

## Direct OPA Commands

You can also use OPA directly:

```bash
# Test deny rules
opa eval --data policies/sentry_module.rego \
         --input policies/test_input.json \
         --format pretty \
         "data.terraform.sentry.deny"

# Test warning rules
opa eval --data policies/sentry_module.rego \
         --input policies/test_input.json \
         --format pretty \
         "data.terraform.sentry.warn"

# Get policy summary
opa eval --data policies/sentry_module.rego \
         --input policies/test_input.json \
         --format pretty \
         "data.terraform.sentry.policy_summary"

# Test a specific rule
opa eval --data policies/sentry_module.rego \
         --input policies/test_input.json \
         "data.terraform.sentry.valid_platforms"
```

## Integration with Buildkite

Add to your `.buildkite/pipeline.yml`:

```yaml
- label: ":shield: OPA Policy Validation"
  key: "opa-validation"
  command: |
    # Generate input from terraform.tfvars
    powershell -Command {
      # Convert tfvars to JSON for OPA
      # (Custom logic based on your tfvars format)
    }
    powershell -ExecutionPolicy Bypass -File scripts/Test-OPAPolicies.ps1 -FailOnWarnings
  agents:
    queue: "windows"
```

## Customizing Policies

Edit `policies/sentry_module.rego` to add or modify rules:

```rego
# Add a custom deny rule
deny contains msg if {
    projects := get_projects(input)
    some project_key, project_config in projects
    project_config.platform == "legacy"
    msg := sprintf("Project '%s' uses deprecated 'legacy' platform", [project_key])
}

# Add a custom warning
warn contains msg if {
    teams := get_teams(input)
    some team_key, team_config in teams
    contains(team_config.name, "temp")
    msg := sprintf("Team '%s' appears to be temporary, consider renaming", [team_key])
}
```

## Testing Policies

Create test cases in `policies/test_input.json`:

```json
{
  "organization_slug": "test-org",
  "teams": {
    "test_team": {
      "name": "Test Team"
    }
  },
  "projects": {
    "test_project": {
      "name": "Test Project",
      "platform": "python",
      "teams": ["test_team"]
    }
  }
}
```

## Policy Development

Use the OPA REPL for interactive development:

```bash
opa run policies/sentry_module.rego policies/test_input.json
```

In the REPL:
```
> data.terraform.sentry.deny
> data.terraform.sentry.warn
> data.terraform.sentry.valid_platforms
```

## CI/CD Integration

The policies can be integrated into:
- ✅ Pre-commit hooks (validate before commit)
- ✅ Buildkite pipeline (validate before deployment)
- ✅ Pull request checks (validate configuration changes)
- ✅ Local development (validate during module development)

## Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Playground](https://play.openpolicyagent.org/)
- [Terraform OPA Policies Examples](https://github.com/open-policy-agent/library)
