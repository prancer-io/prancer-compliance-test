package rule

#
# PR-GCP-GDF-BQ-001
#

default storage_encrypt = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

vulnerable_iam_members = ["allUsers", "allAuthenticatedUsers"]
vulnerable_roles = ["roles/editor", "roles/owner"]

gc_issue["storage_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "bigquery.v2.dataset"
    access := resource.properties.access[_]
    lower(access.role) == vulnerable_roles[_]
    lower(access.iamMember) == vulnerable_iam_members[_]
}

storage_encrypt {
    lower(input.resources[i].type) == "bigquery.v2.dataset"
    not gc_issue["storage_encrypt"]
}

storage_encrypt = false {
    gc_issue["storage_encrypt"]
}

storage_encrypt_err = "Ensure Big Query Datasets are not publically accessible" {
    gc_issue["storage_encrypt"]
}

storage_encrypt_metadata := {
    "Policy Code": "PR-GCP-GDF-BQ-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure Big Query Datasets are not publically accessible",
    "Policy Description": "Ensure there are no anonymously and/or publicly accessible BigQuery datasets available within your Google Cloud Platform (GCP) account. Google Cloud BigQuery datasets have Identity and Access Management (IAM) policies configured to determine who can have access to these resources",
    "Resource Type": "bigquery.v2.dataset",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
}


#
# PR-GCP-GDF-SQL-001
#

default storage_sql_skip_show_database = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

gc_issue["storage_sql_skip_show_database"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "mysql")
    count([c| contains(lower(resource.properties.settings.databaseFlags[_].name), "skip_show_database"); c:=1 ]) == 0
}

gc_issue["storage_sql_skip_show_database"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "mysql")
    count([c| contains(lower(resource.properties.settings.databaseFlags[j].name), "skip_show_database"); not contains(lower(resource.properties.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_skip_show_database {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_sql_skip_show_database"]
}

storage_sql_skip_show_database = false {
    gc_issue["storage_sql_skip_show_database"]
}

storage_sql_skip_show_database_err = "Ensure GCP MySQL instance database flag skip_show_database is set to on" {
    gc_issue["storage_sql_skip_show_database"]
}

storage_sql_skip_show_database_metadata := {
    "Policy Code": "PR-GCP-GDF-SQL-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP MySQL instance database flag skip_show_database is set to on",
    "Policy Description": "This policy identifies Mysql database instances in which database flag skip_show_database is not set to on. This prevents people from using the SHOW DATABASES statement if they do not have the SHOW DATABASES privilege. This can improve security if you have concerns about users being able to see databases belonging to other users. It is recommended to set skip_show_database to on.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-GDF-SQL-002
#

default storage_sql_local_infile = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

gc_issue["storage_sql_local_infile"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "mysql")
    count([c| contains(lower(resource.properties.settings.databaseFlags[_].name), "local_infile"); c:=1 ]) == 0
}

gc_issue["storage_sql_local_infile"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "mysql")
    count([c| contains(lower(resource.properties.settings.databaseFlags[j].name), "local_infile"); contains(lower(resource.properties.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_local_infile {
    lower(input.resources[i].type) == available_types[_]
    not gc_issue["storage_sql_local_infile"]
}

storage_sql_local_infile = false {
    gc_issue["storage_sql_local_infile"]
}

storage_sql_local_infile_err = "Ensure GCP MySQL instance with local_infile database flag is not enabled" {
    gc_issue["storage_sql_local_infile"]
}

storage_sql_local_infile_metadata := {
    "Policy Code": "PR-GCP-GDF-SQL-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP MySQL instance with local_infile database flag is not enabled",
    "Policy Description": "This policy identifies MySQL instances in which local_infile database flag is not disabled. The local_infile flag controls the server-side LOCAL capability for LOAD DATA statements. Based on the settings in local_infile server refuses or permits local data loading by clients. Disabling the local_infile flag setting, would disable the local data loading by clients that have LOCAL enabled on the client side.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-GDF-PSQL-001
#

default storage_psql_log_connections = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

gc_issue["storage_psql_log_connections"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[_].name), "log_connections"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_connections"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[j].name), "log_connections"); contains(lower(resource.properties.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
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
    "Policy Code": "PR-GCP-GDF-PSQL-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_connections is enabled",
    "Policy Description": "This policy identifies PostgreSQL type SQL instances for which the log_connections database flag is disabled. PostgreSQL does not log attempted connections by default. Enabling the log_connections setting will create log entries for each attempted connection as well as successful completion of client authentication which can be useful in troubleshooting issues and to determine any unusual connection attempts to the server.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-GDF-PSQL-002
#

default storage_psql_log_disconnections = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

gc_issue["storage_psql_log_disconnections"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[_].name), "log_disconnections"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_disconnections"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "running"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[j].name), "log_disconnections"); contains(lower(resource.properties.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
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
    "Policy Code": "PR-GCP-GDF-PSQL-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_disconnections is enabled",
    "Policy Description": "This policy identifies PostgreSQL type SQL instances for which the log_disconnections database flag is disabled. Enabling the log_disconnections setting will create log entries at the end of each session which can be useful in troubleshooting issues and determine any unusual activity across a time period.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-GDF-PSQL-003
#

default storage_psql_log_duration = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

gc_issue["storage_psql_log_duration"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "runnable"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[_].name), "log_duration"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_duration"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "runnable"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[j].name), "log_duration"); contains(lower(resource.properties.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
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
    "Policy Code": "PR-GCP-GDF-PSQL-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_duration is set to on",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_duration is not set to on. Enabling the log_duration setting causes the duration of each completed statement to be logged. Monitoring the time taken to execute the queries can be crucial in identifying any resource-hogging queries and assessing the performance of the server. Further steps such as load balancing and the use of optimized queries can be taken to ensure the performance and stability of the server. It is recommended to set log_duration as on.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-GDF-PSQL-004
#

default storage_psql_log_error_verbosity = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

gc_issue["storage_psql_log_error_verbosity"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "runnable"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[_].name), "log_error_verbosity"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_error_verbosity"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "runnable"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[j].name), "log_error_verbosity"); contains(lower(resource.properties.settings.databaseFlags[j].value), "verbose"); c:=1 ]) != 0
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
    "Policy Code": "PR-GCP-GDF-PSQL-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_error_verbosity is set to default or stricter",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_error_verbosity is not set to default. The flag log_error_verbosity controls the amount of detail written in the server log for each message that is logged. Valid values are TERSE, DEFAULT, and VERBOSE. It is recommended to set log_error_verbosity to default or terse.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-GDF-PSQL-005
#

default storage_psql_log_executor_stats = null
available_types = ["sqladmin.v1beta4.instance", "gcp-types/sqladmin-v1beta4:instances"]

gc_issue["storage_psql_log_executor_stats"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "runnable"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[_].name), "log_executor_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_executor_stats"] {
    resource := input.resources[i]
    lower(resource.type) == available_types[_]
    lower(resource.properties.state) == "runnable"
    contains(lower(resource.properties.databaseVersion), "postgres")
    count([c| contains(lower(resource.properties.settings.databaseFlags[j].name), "log_executor_stats"); contains(lower(resource.properties.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
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
    "Policy Code": "PR-GCP-GDF-PSQL-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_executor_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_executor_stats is not set to off. The log_executor_stats flag enables a crude profiling method for logging PostgreSQL executor performance statistics. Even though it can be useful for troubleshooting, it may increase the number of logs significantly and have performance overhead. It is recommended to set log_executor_stats off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}
