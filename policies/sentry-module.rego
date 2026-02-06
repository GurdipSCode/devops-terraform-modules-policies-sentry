package terraform.sentry

import rego.v1

####################
# HELPER FUNCTIONS
####################

is_create_organization(config) := config.create_organization == true

has_organization_name(config) := config.organization_name != ""

get_projects(config) := config.projects

get_teams(config) := config.teams

get_issue_alerts(config) := config.issue_alerts

get_metric_alerts(config) := config.metric_alerts

####################
# ORGANIZATION POLICIES
####################

deny contains msg if {
    is_create_organization(input)
    not has_organization_name(input)
    msg := "When create_organization is true, organization_name must be provided"
}

deny contains msg if {
    org_slug := input.organization_slug
    not regex.match(`^[a-z0-9-]+$`, org_slug)
    msg := sprintf("organization_slug '%s' must contain only lowercase letters, numbers, and hyphens", [org_slug])
}

deny contains msg if {
    org_slug := input.organization_slug
    count(org_slug) > 50
    msg := sprintf("organization_slug '%s' exceeds maximum length of 50 characters", [org_slug])
}

####################
# TEAM POLICIES
####################

deny contains msg if {
    teams := get_teams(input)
    count(teams) == 0
    msg := "At least one team must be defined for proper access control"
}

deny contains msg if {
    teams := get_teams(input)
    some team_key, team_config in teams
    team_config.name == ""
    msg := sprintf("Team '%s' has an empty name", [team_key])
}

deny contains msg if {
    teams := get_teams(input)
    some team_key, team_config in teams
    count(team_config.name) > 64
    msg := sprintf("Team '%s' name exceeds 64 characters: '%s'", [team_key, team_config.name])
}

warn contains msg if {
    teams := get_teams(input)
    some team_key, team_config in teams
    not regex.match(`^[A-Z]`, team_config.name)
    msg := sprintf("Team '%s' name should start with a capital letter: '%s'", [team_key, team_config.name])
}

####################
# PROJECT POLICIES
####################

deny contains msg if {
    projects := get_projects(input)
    count(projects) == 0
    msg := "At least one project must be defined"
}

deny contains msg if {
    projects := get_projects(input)
    some project_key, project_config in projects
    project_config.name == ""
    msg := sprintf("Project '%s' has an empty name", [project_key])
}

deny contains msg if {
    projects := get_projects(input)
    some project_key, project_config in projects
    count(project_config.teams) == 0
    msg := sprintf("Project '%s' must be assigned to at least one team", [project_key])
}

deny contains msg if {
    projects := get_projects(input)
    teams := get_teams(input)
    some project_key, project_config in projects
    some team_name in project_config.teams
    not team_name in object.keys(teams)
    msg := sprintf("Project '%s' references non-existent team '%s'", [project_key, team_name])
}

valid_platforms := [
    "python", "javascript", "node", "go", "ruby", "php", "java",
    "csharp", "dotnet", "react", "vue", "angular", "django", "flask",
    "express", "other"
]

deny contains msg if {
    projects := get_projects(input)
    some project_key, project_config in projects
    not project_config.platform in valid_platforms
    msg := sprintf("Project '%s' has invalid platform '%s'. Valid platforms: %s", [
        project_key, 
        project_config.platform,
        concat(", ", valid_platforms)
    ])
}

warn contains msg if {
    projects := get_projects(input)
    some project_key, project_config in projects
    project_config.resolve_age
    project_config.resolve_age < 1
    msg := sprintf("Project '%s' has resolve_age < 1 hour, which may auto-resolve issues too quickly", [project_key])
}

warn contains msg if {
    projects := get_projects(input)
    some project_key, project_config in projects
    project_config.resolve_age
    project_config.resolve_age > 720
    msg := sprintf("Project '%s' has resolve_age > 30 days (720 hours), issues may never auto-resolve", [project_key])
}

####################
# ISSUE ALERT POLICIES
####################

deny contains msg if {
    alerts := get_issue_alerts(input)
    projects := get_projects(input)
    some alert_key, alert_config in alerts
    not alert_config.project in object.keys(projects)
    msg := sprintf("Issue alert '%s' references non-existent project '%s'", [alert_key, alert_config.project])
}

deny contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key, alert_config in alerts
    alert_config.name == ""
    msg := sprintf("Issue alert '%s' has an empty name", [alert_key])
}

deny contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key, alert_config in alerts
    not alert_config.action_match in ["any", "all", "none"]
    msg := sprintf("Issue alert '%s' has invalid action_match '%s'. Must be: any, all, or none", [
        alert_key,
        alert_config.action_match
    ])
}

deny contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key, alert_config in alerts
    not alert_config.filter_match in ["any", "all", "none"]
    msg := sprintf("Issue alert '%s' has invalid filter_match '%s'. Must be: any, all, or none", [
        alert_key,
        alert_config.filter_match
    ])
}

deny contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key, alert_config in alerts
    alert_config.frequency < 5
    msg := sprintf("Issue alert '%s' has frequency < 5 minutes, which may cause alert fatigue", [alert_key])
}

deny contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key, alert_config in alerts
    alert_config.frequency > 10080
    msg := sprintf("Issue alert '%s' has frequency > 1 week (10080 minutes), alerts may be too infrequent", [alert_key])
}

warn contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key, alert_config in alerts
    count(alert_config.conditions) == 0
    msg := sprintf("Issue alert '%s' has no conditions defined", [alert_key])
}

warn contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key, alert_config in alerts
    count(alert_config.actions) == 0
    msg := sprintf("Issue alert '%s' has no actions defined (alert will not notify anyone)", [alert_key])
}

####################
# METRIC ALERT POLICIES
####################

deny contains msg if {
    alerts := get_metric_alerts(input)
    projects := get_projects(input)
    some alert_key, alert_config in alerts
    not alert_config.project in object.keys(projects)
    msg := sprintf("Metric alert '%s' references non-existent project '%s'", [alert_key, alert_config.project])
}

deny contains msg if {
    alerts := get_metric_alerts(input)
    some alert_key, alert_config in alerts
    alert_config.time_window < 1
    msg := sprintf("Metric alert '%s' has time_window < 1 minute", [alert_key])
}

deny contains msg if {
    alerts := get_metric_alerts(input)
    some alert_key, alert_config in alerts
    alert_config.time_window > 1440
    msg := sprintf("Metric alert '%s' has time_window > 24 hours (1440 minutes)", [alert_key])
}

deny contains msg if {
    alerts := get_metric_alerts(input)
    some alert_key, alert_config in alerts
    not alert_config.threshold_type in ["above", "below"]
    msg := sprintf("Metric alert '%s' has invalid threshold_type '%s'. Must be: above or below", [
        alert_key,
        alert_config.threshold_type
    ])
}

warn contains msg if {
    alerts := get_metric_alerts(input)
    some alert_key, alert_config in alerts
    count(alert_config.triggers) == 0
    msg := sprintf("Metric alert '%s' has no triggers defined", [alert_key])
}

warn contains msg if {
    alerts := get_metric_alerts(input)
    some alert_key, alert_config in alerts
    count(alert_config.triggers) > 3
    msg := sprintf("Metric alert '%s' has more than 3 triggers, consider simplifying", [alert_key])
}

####################
# NAMING CONVENTION POLICIES
####################

warn contains msg if {
    projects := get_projects(input)
    some project_key in object.keys(projects)
    not regex.match(`^[a-z][a-z0-9_]*$`, project_key)
    msg := sprintf("Project key '%s' should follow snake_case naming convention", [project_key])
}

warn contains msg if {
    teams := get_teams(input)
    some team_key in object.keys(teams)
    not regex.match(`^[a-z][a-z0-9_]*$`, team_key)
    msg := sprintf("Team key '%s' should follow snake_case naming convention", [team_key])
}

warn contains msg if {
    alerts := get_issue_alerts(input)
    some alert_key in object.keys(alerts)
    not regex.match(`^[a-z][a-z0-9_]*$`, alert_key)
    msg := sprintf("Issue alert key '%s' should follow snake_case naming convention", [alert_key])
}

####################
# SECURITY POLICIES
####################

warn contains msg if {
    count(get_teams(input)) > 20
    msg := "Large number of teams (>20) detected. Consider reviewing team structure for maintainability"
}

warn contains msg if {
    count(get_projects(input)) > 50
    msg := "Large number of projects (>50) detected. Consider splitting into multiple modules or organizations"
}

warn contains msg if {
    count(get_issue_alerts(input)) > 100
    msg := "Large number of issue alerts (>100) detected. Consider consolidating alerts to reduce noise"
}

####################
# BEST PRACTICES
####################

warn contains msg if {
    projects := get_projects(input)
    alerts := get_issue_alerts(input)
    some project_key in object.keys(projects)
    project_alerts := [a | some ak, ac in alerts; ac.project == project_key; a := ak]
    count(project_alerts) == 0
    msg := sprintf("Project '%s' has no alerts configured. Consider adding monitoring", [project_key])
}

warn contains msg if {
    projects := get_projects(input)
    some project_key, project_config in projects
    count(project_config.teams) > 5
    msg := sprintf("Project '%s' is assigned to more than 5 teams. Consider reducing team assignments", [project_key])
}

####################
# POLICY SUMMARY
####################

policy_summary := {
    "total_denies": count(deny),
    "total_warnings": count(warn),
    "policies_evaluated": [
        "organization_validation",
        "team_validation",
        "project_validation",
        "issue_alert_validation",
        "metric_alert_validation",
        "naming_conventions",
        "security_checks",
        "best_practices"
    ]
}
