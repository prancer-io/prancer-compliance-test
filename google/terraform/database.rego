package rule

#
# PR-GCP-TRF-BQ-001
#

default bq_public_access = null
vulnerable_roles = ["editor", "owner"]

gc_issue["bq_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "google_bigquery_dataset"
    access := resource.properties.access[_]
    lower(access.role) == vulnerable_roles[_]
    lower(access.special_group) == "allauthenticatedusers"
}

bq_public_access {
    lower(input.resources[i].type) == "google_bigquery_dataset"
    not gc_issue["bq_public_access"]
}

bq_public_access = false {
    gc_issue["bq_public_access"]
}

bq_public_access_err = "Ensure Big Query Datasets are not publically accessible" {
    gc_issue["bq_public_access"]
}

bq_public_access_metadata := {
    "Policy Code": "PR-GCP-TRF-BQ-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure Big Query Datasets are not publically accessible",
    "Policy Description": "Ensure there are no anonymously and/or publicly accessible BigQuery datasets available within your Google Cloud Platform (GCP) account. Google Cloud BigQuery datasets have Identity and Access Management (IAM) policies configured to determine who can have access to these resources",
    "Resource Type": "google_bigquery_dataset",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
}


#
# PR-GCP-TRF-PSQL-001
#

default storage_psql_log_connections = null

gc_issue["storage_psql_log_connections"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_connections"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_connections"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_connections"); contains(lower(resource.properties.settings.database_flags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_connections {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_connections"]
}

storage_psql_log_connections = false {
    gc_issue["storage_psql_log_connections"]
}

storage_psql_log_connections_err = "Ensure GCP PostgreSQL instance database flag log_connections is enabled" {
    gc_issue["storage_psql_log_connections"]
}

storage_psql_log_connections_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_connections is enabled",
    "Policy Description": "This policy identifies PostgreSQL type SQL instances for which the log_connections database flag is disabled. PostgreSQL does not log attempted connections by default. Enabling the log_connections setting will create log entries for each attempted connection as well as successful completion of client authentication which can be useful in troubleshooting issues and to determine any unusual connection attempts to the server.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-002
#

default storage_psql_log_disconnections = null

gc_issue["storage_psql_log_disconnections"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_disconnections"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_disconnections"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_disconnections"); contains(lower(resource.properties.settings.database_flags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_disconnections {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_disconnections"]
}

storage_psql_log_disconnections = false {
    gc_issue["storage_psql_log_disconnections"]
}

storage_psql_log_disconnections_err = "Ensure GCP PostgreSQL instance database flag log_disconnections is enabled" {
    gc_issue["storage_psql_log_disconnections"]
}

storage_psql_log_disconnections_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_disconnections is enabled",
    "Policy Description": "This policy identifies PostgreSQL type SQL instances for which the log_disconnections database flag is disabled. Enabling the log_disconnections setting will create log entries at the end of each session which can be useful in troubleshooting issues and determine any unusual activity across a time period.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-003
#

default storage_psql_log_duration = null

gc_issue["storage_psql_log_duration"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_duration"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_duration"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_duration"); contains(lower(resource.properties.settings.database_flags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_duration {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_duration"]
}

storage_psql_log_duration = false {
    gc_issue["storage_psql_log_duration"]
}

storage_psql_log_duration_err = "Ensure GCP PostgreSQL instance database flag log_duration is set to on" {
    gc_issue["storage_psql_log_duration"]
}

storage_psql_log_duration_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_duration is set to on",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_duration is not set to on. Enabling the log_duration setting causes the duration of each completed statement to be logged. Monitoring the time taken to execute the queries can be crucial in identifying any resource-hogging queries and assessing the performance of the server. Further steps such as load balancing and the use of optimized queries can be taken to ensure the performance and stability of the server. It is recommended to set log_duration as on.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-004
#

default storage_psql_log_error_verbosity = null

gc_issue["storage_psql_log_error_verbosity"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_error_verbosity"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_error_verbosity"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_error_verbosity"); contains(lower(resource.properties.settings.database_flags[j].value), "verbose"); c:=1 ]) != 0
}

storage_psql_log_error_verbosity {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_error_verbosity"]
}

storage_psql_log_error_verbosity = false {
    gc_issue["storage_psql_log_error_verbosity"]
}

storage_psql_log_error_verbosity_err = "Ensure GCP PostgreSQL instance database flag log_error_verbosity is set to default or stricter" {
    gc_issue["storage_psql_log_error_verbosity"]
}

storage_psql_log_error_verbosity_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_error_verbosity is set to default or stricter",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_error_verbosity is not set to default. The flag log_error_verbosity controls the amount of detail written in the server log for each message that is logged. Valid values are TERSE, DEFAULT, and VERBOSE. It is recommended to set log_error_verbosity to default or terse.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-005
#

default storage_psql_log_executor_stats = null

gc_issue["storage_psql_log_executor_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_executor_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_executor_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_executor_stats"); contains(lower(resource.properties.settings.database_flags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_executor_stats {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_executor_stats"]
}

storage_psql_log_executor_stats = false {
    gc_issue["storage_psql_log_executor_stats"]
}

storage_psql_log_executor_stats_err = "Ensure GCP PostgreSQL instance database flag log_executor_stats is set to off" {
    gc_issue["storage_psql_log_executor_stats"]
}

storage_psql_log_executor_stats_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_executor_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_executor_stats is not set to off. The log_executor_stats flag enables a crude profiling method for logging PostgreSQL executor performance statistics. Even though it can be useful for troubleshooting, it may increase the number of logs significantly and have performance overhead. It is recommended to set log_executor_stats off.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-006
#

default storage_psql_log_hostname = null

gc_issue["storage_psql_log_hostname"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_hostname"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_hostname"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_hostname"); contains(lower(resource.properties.settings.database_flags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_hostname {
    lower(input.resources[i].type) == "google_sql_database_instance"
    not gc_issue["storage_psql_log_hostname"]
}

storage_psql_log_hostname = false {
    gc_issue["storage_psql_log_hostname"]
}

storage_psql_log_hostname_err = "GCP PostgreSQL instance database flag log_hostname is not set to off" {
    gc_issue["storage_psql_log_hostname"]
}

storage_psql_log_hostname_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP PostgreSQL instance database flag log_hostname is not set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_hostname is not set to off. Logging hostnames can incur overhead on server performance as for each statement logged, DNS resolution will be required to convert IP address to hostname. It is recommended to set log_hostname as off.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-007
#

default storage_psql_log_lock_waits = null

gc_issue["storage_psql_log_lock_waits"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_lock_waits"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_lock_waits"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_lock_waits"); contains(lower(resource.properties.settings.database_flags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_lock_waits {
    lower(input.resources[i].type) == "google_sql_database_instance"
    not gc_issue["storage_psql_log_lock_waits"]
}

storage_psql_log_lock_waits = false {
    gc_issue["storage_psql_log_lock_waits"]
}

storage_psql_log_lock_waits_err = "Ensure GCP PostgreSQL instance database flag log_lock_waits is enabled" {
    gc_issue["storage_psql_log_lock_waits"]
}

storage_psql_log_lock_waits_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_lock_waits is enabled",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_lock_waits is not set. Enabling the log_lock_waits flag can be used to identify poor performance due to locking delays or if a specially-crafted SQL is attempting to starve resources through holding locks for excessive amounts of time.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-TRF-PSQL-008
#

default storage_psql_log_min_duration_statement = null

gc_issue["storage_psql_log_min_duration_statement"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_min_duration_statement"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_min_duration_statement"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_min_duration_statement"); resource.properties.settings.database_flags[j].value != -1; c:=1 ]) != 0
}

storage_psql_log_min_duration_statement {
    lower(input.resources[i].type) == "google_sql_database_instance"
    not gc_issue["storage_psql_log_min_duration_statement"]
}

storage_psql_log_min_duration_statement = false {
    gc_issue["storage_psql_log_min_duration_statement"]
}

storage_psql_log_min_duration_statement_err = "Ensure GCP PostgreSQL instance database flag log_min_duration_statement is set to -1" {
    gc_issue["storage_psql_log_min_duration_statement"]
}

storage_psql_log_min_duration_statement_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_min_duration_statement is set to -1",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_min_duration_statement is not set to -1. The log_min_duration_statement flag defines the minimum amount of execution time of a statement in milliseconds where the total duration of the statement is logged. Logging SQL statements may include sensitive information that should not be recorded in logs. So it is recommended to set  log_min_duration_statement flag value to -1 so that execution statements logging will be disabled.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-009
#

default storage_psql_log_min_messages = null

gc_issue["storage_psql_log_min_messages"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_min_messages"); c:=1 ]) == 0
}

storage_psql_log_min_messages {
    lower(input.resources[i].type) == "google_sql_database_instance"
    not gc_issue["storage_psql_log_min_messages"]
}

storage_psql_log_min_messages = false {
    gc_issue["storage_psql_log_min_messages"]
}

storage_psql_log_min_messages_err = "Ensure GCP PostgreSQL instance database flag log_min_messages is set" {
    gc_issue["storage_psql_log_min_messages"]
}

storage_psql_log_min_messages_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_min_messages is set",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_min_messages is not set. The log_min_messages flag controls which message levels are written to the server log, valid values are DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC. Each level includes all the levels that follow it. log_min_messages flag value changes should only be made in accordance with the organization's logging policy. Auditing helps in troubleshooting operational problems and also permits forensic analysis.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-TRF-PSQL-010
#

default storage_psql_log_parser_stats = null

gc_issue["storage_psql_log_parser_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_parser_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_parser_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_parser_stats"); contains(lower(resource.properties.settings.database_flags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_parser_stats {
    lower(input.resources[i].type) == "google_sql_database_instance"
    not gc_issue["storage_psql_log_parser_stats"]
}

storage_psql_log_parser_stats = false {
    gc_issue["storage_psql_log_parser_stats"]
}

storage_psql_log_parser_stats_err = "Ensure GCP PostgreSQL instance database flag log_parser_stats is set to off" {
    gc_issue["storage_psql_log_parser_stats"]
}

storage_psql_log_parser_stats_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_parser_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_parser_stats is not set to off. The PostgreSQL planner/optimizer is responsible to parse and verify the syntax of each query received by the server. The log_parser_stats flag enables a crude profiling method for logging parser performance statistics. Even though it can be useful for troubleshooting, it may increase the number of logs significantly and have performance overhead. It is recommended to set log_parser_stats as off.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-TRF-PSQL-011
#

default storage_psql_log_planner_stats = null

gc_issue["storage_psql_log_planner_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_planner_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_planner_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_planner_stats"); contains(lower(resource.properties.settings.database_flags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_planner_stats {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_planner_stats"]
}

storage_psql_log_planner_stats = false {
    gc_issue["storage_psql_log_planner_stats"]
}

storage_psql_log_planner_stats_err = "Ensure GCP PostgreSQL instance database flag log_planner_stats is set to off" {
    gc_issue["storage_psql_log_planner_stats"]
}

storage_psql_log_planner_stats_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_planner_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_planner_stats is not set to off. The PostgreSQL planner/optimizer is responsible to create an optimal execution plan for each query. The log_planner_stats flag controls the inclusion of PostgreSQL planner performance statistics in the PostgreSQL logs for each query. This can be useful for troubleshooting but may increase the number of logs significantly and have performance overhead. It is recommended to set log_planner_stats off.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-TRF-PSQL-012
#

default storage_psql_log_statement = null

storage_psql_log_statement_issue_values = ["all", "none"]

gc_issue["storage_psql_log_statement"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_statement"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_statement"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_statement"); contains(lower(resource.properties.settings.database_flags[j].value), storage_psql_log_statement_issue_values[_]); c:=1 ]) != 0
}

storage_psql_log_statement {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_statement"]
}

storage_psql_log_statement = false {
    gc_issue["storage_psql_log_statement"]
}

storage_psql_log_statement_err = "Ensure GCP PostgreSQL instance database flag log_statement is set appropriately" {
    gc_issue["storage_psql_log_statement"]
}

storage_psql_log_statement_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_statement is set appropriately",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_statement is not set appropriately. If log_statement is not set to a correct value may lead to too many statements or too few statements. Setting log_statement to align with your organization's security and logging policies facilitates later auditing and review of database activities. It is recommended to choose an appropriate value (ddl or mod) for the flag log_statement.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}



#
# PR-GCP-TRF-PSQL-013
#

default storage_psql_log_statement_stats = null

gc_issue["storage_psql_log_statement_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_statement_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_statement_stats"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_statement_stats"); contains(lower(resource.properties.settings.database_flags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_statement_stats {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_statement_stats"]
}

storage_psql_log_statement_stats = false {
    gc_issue["storage_psql_log_statement_stats"]
}

storage_psql_log_statement_stats_err = "Ensure GCP PostgreSQL instance database flag log_statement_stats is set to off" {
    gc_issue["storage_psql_log_statement_stats"]
}

storage_psql_log_statement_stats_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_statement_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_statement_stats is not set to off. The PostgreSQL planner/optimizer is responsible to create an optimal execution plan for each query. The log_planner_stats flag controls the inclusion of PostgreSQL planner performance statistics in the PostgreSQL logs for each query. This can be useful for troubleshooting but may increase the number of logs significantly and have performance overhead. It is recommended to set log_planner_stats off.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-TRF-PSQL-014
#

default storage_psql_log_temp_files = null

gc_issue["storage_psql_log_temp_files"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_temp_files"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_temp_files"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_temp_files"); resource.properties.settings.database_flags[j].value != 0; c:=1 ]) != 0
}

storage_psql_log_temp_files {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_temp_files"]
}

storage_psql_log_temp_files = false {
    gc_issue["storage_psql_log_temp_files"]
}

storage_psql_log_temp_files_err = "Ensure GCP PostgreSQL instance database flag log_temp_files is set to 0" {
    gc_issue["storage_psql_log_temp_files"]
}

storage_psql_log_temp_files_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_temp_files is set to 0",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_temp_files is not set to 0. The log_temp_files flag controls the logging of names and size of temporary files. Configuring log_temp_files to 0 causes all temporary file information to be logged, while positive values log only files whose size is greater than or equal to the specified number of kilobytes. A value of -1 disables temporary file information logging. If all temporary files are not logged, it may be more difficult to identify potential performance issues that may be either poor application coding or deliberate resource starvation attempts.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-TRF-PSQL-015
#

default storage_psql_log_checkpoints = null


gc_issue["storage_psql_log_checkpoints"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[_].name), "log_checkpoints"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_checkpoints"] {
    resource := input.resources[i]
    lower(resource.type) == "google_sql_database_instance"
    contains(lower(resource.properties.database_version), "postgres")
    count([c| contains(lower(resource.properties.settings.database_flags[j].name), "log_checkpoints"); contains(lower(resource.properties.settings.database_flags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_checkpoints {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_psql_log_checkpoints"]
}

storage_psql_log_checkpoints = false {
    gc_issue["storage_psql_log_checkpoints"]
}

storage_psql_log_checkpoints_err = "Ensure GCP PostgreSQL instance with log_checkpoints database flag is enabled" {
    gc_issue["storage_psql_log_checkpoints"]
}

storage_psql_log_checkpoints_metadata := {
    "Policy Code": "PR-GCP-TRF-PSQL-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP PostgreSQL instance with log_checkpoints database flag is enabled",
    "Policy Description": "This policy identifies PostgreSQL instances in which log_checkpoints database flag is not set. Enabling the log_checkpoints database flag would enable logging of checkpoints and restart points to the server log.",
    "Resource Type": "google_sql_database_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}
