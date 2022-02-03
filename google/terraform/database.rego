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
