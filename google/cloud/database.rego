package rule

import data.common

#
# PR-GCP-CLD-BQ-001
#

default bigquery_datasets_dont_have_public_access = null
vulnerable_iam_members = ["allusers", "allauthenticatedusers"]
vulnerable_roles = ["roles/editor", "roles/owner"]

gcp_issue["bigquery_datasets_dont_have_public_access"] {
    access := input.access[_]
    lower(access.iamMember) == vulnerable_iam_members[_]
}

bigquery_datasets_dont_have_public_access {
    not gcp_issue["bigquery_datasets_dont_have_public_access"]
}

bigquery_datasets_dont_have_public_access = false {
    gcp_issue["bigquery_datasets_dont_have_public_access"]
}

bigquery_datasets_dont_have_public_access_err = "BigQuery dataset currently publically accessible" {
    gcp_issue["bigquery_datasets_dont_have_public_access"]
}

bigquery_datasets_dont_have_public_access_metadata := {
    "Policy Code": "PR-GCP-CLD-BQ-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure BigQuery datasets are not publicly accessible",
    "Policy Description": "Ensure there are no anonymously and/or publicly accessible BigQuery datasets available within your Google Cloud Platform (GCP) account. Google Cloud BigQuery datasets have Identity and Access Management (IAM) policies configured to determine who can have access to these resources",
    "Resource Type": "bigquery.v2.dataset",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
}

#
# PR-GCP-CLD-PSQL-006
#

default storage_psql_log_hostname = null

gc_issue["storage_psql_log_hostname"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_hostname"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_hostname"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_hostname"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_hostname {
    not gc_issue["storage_psql_log_hostname"]
}

storage_psql_log_hostname = false {
    gc_issue["storage_psql_log_hostname"]
}

storage_psql_log_hostname_err = "GCP PostgreSQL instance database flag log_hostname is not set to off" {
    gc_issue["storage_psql_log_hostname"]
}

storage_psql_log_hostname_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP PostgreSQL instance database flag log_hostname is not set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_hostname is not set to off. Logging hostnames can incur overhead on server performance as for each statement logged, DNS resolution will be required to convert IP address to hostname. It is recommended to set log_hostname as off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-001
#

default storage_sql_skip_show_database = null

gc_issue["storage_sql_skip_show_database"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "mysql")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "skip_show_database"); c:=1 ]) == 0
}

gc_issue["storage_sql_skip_show_database"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "mysql")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "skip_show_database"); not contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_skip_show_database {
    not gc_issue["storage_sql_skip_show_database"]
}

storage_sql_skip_show_database = false {
    gc_issue["storage_sql_skip_show_database"]
}

storage_sql_skip_show_database_err = "Ensure GCP MySQL instance database flag skip_show_database is set to on" {
    gc_issue["storage_sql_skip_show_database"]
}

storage_sql_skip_show_database_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP MySQL instance database flag skip_show_database is set to on",
    "Policy Description": "This policy identifies Mysql database instances in which database flag skip_show_database is not set to on. This prevents people from using the SHOW DATABASES statement if they do not have the SHOW DATABASES privilege. This can improve security if you have concerns about users being able to see databases belonging to other users. It is recommended to set skip_show_database to on.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-007
#

default storage_psql_log_lock_waits = null

gc_issue["storage_psql_log_lock_waits"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_lock_waits"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_lock_waits"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_lock_waits"); contains(lower(input.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_lock_waits {
    not gc_issue["storage_psql_log_lock_waits"]
}

storage_psql_log_lock_waits = false {
    gc_issue["storage_psql_log_lock_waits"]
}

storage_psql_log_lock_waits_err = "Ensure GCP PostgreSQL instance database flag log_lock_waits is enabled" {
    gc_issue["storage_psql_log_lock_waits"]
}

storage_psql_log_lock_waits_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_lock_waits is enabled",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_lock_waits is not set. Enabling the log_lock_waits flag can be used to identify poor performance due to locking delays or if a specially-crafted SQL is attempting to starve resources through holding locks for excessive amounts of time.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-002
#

default storage_sql_local_infile = null

gc_issue["storage_sql_local_infile"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "mysql")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "local_infile"); c:=1 ]) == 0
}

gc_issue["storage_sql_local_infile"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "mysql")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "local_infile"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_local_infile {
    not gc_issue["storage_sql_local_infile"]
}

storage_sql_local_infile = false {
    gc_issue["storage_sql_local_infile"]
}

storage_sql_local_infile_err = "Ensure GCP MySQL instance with local_infile database flag is not enabled" {
    gc_issue["storage_sql_local_infile"]
}

storage_sql_local_infile_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP MySQL instance with local_infile database flag is not enabled",
    "Policy Description": "This policy identifies MySQL instances in which local_infile database flag is not disabled. The local_infile flag controls the server-side LOCAL capability for LOAD DATA statements. Based on the settings in local_infile server refuses or permits local data loading by clients. Disabling the local_infile flag setting, would disable the local data loading by clients that have LOCAL enabled on the client side.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-003
#

default storage_sql_label_info = null

gc_issue["storage_sql_label_info"] {
    not input.settings.userLabels
}

gc_issue["storage_sql_label_info"] {
    not common.non_empty(input.settings.userLabels)
}

gc_issue["storage_sql_label_info"] {
    input.settings.userLabels == null
}


storage_sql_label_info {
    not gc_issue["storage_sql_label_info"]
}

storage_sql_label_info = false {
    gc_issue["storage_sql_label_info"]
}

storage_sql_label_info_err = "Ensure GCP SQL Instances contains Label information" {
    gc_issue["storage_sql_label_info"]
}

storage_sql_label_info_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL Instances contains Label information",
    "Policy Description": "This policy identifies the SQL DB instance which does not have any Labels. Labels can be used for easy identification and searches.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-004
#

default storage_sql_flag_authentication = null

gc_issue["storage_sql_flag_authentication"] {
    contains(lower(input.databaseVersion), "sqlserver")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "contained database authentication"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_flag_authentication {
    not gc_issue["storage_sql_flag_authentication"]
}

storage_sql_flag_authentication = false {
    gc_issue["storage_sql_flag_authentication"]
}

storage_sql_flag_authentication_err = "Ensure SQL Server instance database flag 'contained database authentication' is disabled" {
    gc_issue["storage_sql_flag_authentication"]
}

storage_sql_flag_authentication_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure SQL Server instance database flag 'contained database authentication' is disabled",
    "Policy Description": "This policy identifies SQL Server instance database flag 'contained database authentication' is enabled. Most of the threats associated with contained database are related to authentication process. So it is recommended to disable this flag.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-005
#

default storage_sql_owner_chaining = null

gc_issue["storage_sql_owner_chaining"] {
    contains(lower(input.databaseVersion), "sqlserver")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "cross db ownership chaining"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_owner_chaining {
    not gc_issue["storage_sql_owner_chaining"]
}

storage_sql_owner_chaining = false {
    gc_issue["storage_sql_owner_chaining"]
}

storage_sql_owner_chaining_err = "Ensure GCP SQL Server instance database flag 'cross db ownership chaining' is disabled" {
    gc_issue["storage_sql_owner_chaining"]
}

storage_sql_owner_chaining_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL Server instance database flag 'cross db ownership chaining' is disabled",
    "Policy Description": "This policy identifies GCP SQL Server instance database flag 'cross db ownership chaining' is enabled. Enabling cross db ownership is not recommended unless all of the databases hosted by the instance of SQL Server must participate in cross-database ownership chaining and you are aware of the security implications of this setting.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-006
#

default storage_sql_automated_backup = null

gc_issue["storage_sql_automated_backup"] {
    not input.settings.backupConfiguration.enabled
    lower(input.instanceType) != "read_replica_instance"
    lower(input.instanceType) != "on_premises_instance"
}

storage_sql_automated_backup {
    not gc_issue["storage_sql_automated_backup"]
}

storage_sql_automated_backup = false {
    gc_issue["storage_sql_automated_backup"]
}

storage_sql_automated_backup_err = "Ensure GCP SQL database instance is configured with automated backups" {
    gc_issue["storage_sql_automated_backup"]
}

storage_sql_automated_backup_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL database instance is configured with automated backups",
    "Policy Description": "This policy identifies GCP SQL Server instance database flag 'cross db ownership chaining' is enabled. Enabling cross db ownership is not recommended unless all of the databases hosted by the instance of SQL Server must participate in cross-database ownership chaining and you are aware of the security implications of this setting.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-007
#

default storage_sql_public_ip = null

gc_issue["storage_sql_public_ip"] {
    lower(input.backendType) == "second_gen"
    ipAddress := input.ipAddresses[_]
    contains(lower(ipAddress.type), "primary")
}

storage_sql_public_ip {
    not gc_issue["storage_sql_public_ip"]
}

storage_sql_public_ip = false {
    gc_issue["storage_sql_public_ip"]
}

storage_sql_public_ip_err = "Ensure GCP SQL database is not assigned with public IP" {
    gc_issue["storage_sql_public_ip"]
}

storage_sql_public_ip_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL database is not assigned with public IP",
    "Policy Description": "This policy identifies GCP SQL databases which are assigned with public IP.  To lower the organisation's attack surface, Cloud SQL databases should not have public IPs. Private IPs provide improved network security and lower latency for your application. It is recommended to configure Second Generation Sql instance to use private IPs instead of public IPs.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-008
#

default storage_sql_overly_permissive = null
issued_ip = ["0.0.0.0/0", "::/0"]

gc_issue["storage_sql_overly_permissive"] {
    lower(input.backendType) == "second_gen"
    authorizedNetwork := input.settings.ipConfiguration.authorizedNetworks[_]
    contains(lower(authorizedNetwork.value), issued_ip[_])
}

storage_sql_overly_permissive {
    not gc_issue["storage_sql_overly_permissive"]
}

storage_sql_overly_permissive = false {
    gc_issue["storage_sql_overly_permissive"]
}

storage_sql_overly_permissive_err = "Ensure GCP SQL instance is not configured with overly permissive authorized networks" {
    gc_issue["storage_sql_overly_permissive"]
}

storage_sql_overly_permissive_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL instance is not configured with overly permissive authorized networks",
    "Policy Description": "This policy identifies GCP Cloud SQL instances that are configured with overly permissive authorized networks. You can connect to the SQL instance securely by using the Cloud SQL Proxy or adding your client's public address as an authorized network. If your client application is connecting directly to a Cloud SQL instance on its public IP address, you have to add your client's external address as an Authorized network for securing the connection. It is recommended to add specific IPs instead of public IPs as authorized networks as per the requirement.\n\nReference: https://cloud.google.com/sql/docs/mysql/authorize-networks",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-009
#

default storage_sql_external_script = null
issued_ip = ["0.0.0.0/0", "::/0"]

gc_issue["storage_sql_external_script"] {
    lower(input.state) == "runnable"
    lower(input.databaseVersion) == "sqlserver"
    count([c| contains(lower(input.settings.databaseFlags[_].name), "external scripts enabled"); c:=1 ]) == 0
}

gc_issue["storage_sql_external_script"] {
    lower(input.state) == "runnable"
    lower(input.databaseVersion) == "sqlserver"
    count([c| contains(lower(input.settings.databaseFlags[j].name), "external scripts enabled"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_external_script {
    not gc_issue["storage_sql_external_script"]
}

storage_sql_external_script = false {
    gc_issue["storage_sql_external_script"]
}

storage_sql_external_script_err = "Ensure GCP SQL server instance database flag external scripts enabled is set to off" {
    gc_issue["storage_sql_external_script"]
}

storage_sql_external_script_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL server instance database flag external scripts enabled is set to off",
    "Policy Description": "This policy identifies GCP SQL server instances for which database flag 'external scripts enabled' is not set to off. Feature 'external scripts enabled' enables the execution of scripts with certain remote language extensions. When Advanced Analytics Services is installed, setup can optionally set this property to true. As the External Scripts Enabled feature allows scripts external to SQL such as files located in an R library to be executed, which could adversely affect the security of the system. It is recommended to set external scripts enabled database flag for Cloud SQL SQL Server instance to off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-010
#

default storage_sql_flag_remote = null
issued_ip = ["0.0.0.0/0", "::/0"]

gc_issue["storage_sql_flag_remote"] {
    lower(input.state) == "runnable"
    lower(input.databaseVersion) == "sqlserver"
    count([c| contains(lower(input.settings.databaseFlags[_].name), "remote access"); c:=1 ]) == 0
}

gc_issue["storage_sql_flag_remote"] {
    lower(input.state) == "runnable"
    lower(input.databaseVersion) == "sqlserver"
    count([c| contains(lower(input.settings.databaseFlags[j].name), "remote access"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_sql_flag_remote {
    not gc_issue["storage_sql_flag_remote"]
}

storage_sql_flag_remote = false {
    gc_issue["storage_sql_flag_remote"]
}

storage_sql_flag_remote_err = "Ensure GCP SQL server instance database flag remote access is set to off" {
    gc_issue["storage_sql_flag_remote"]
}

storage_sql_flag_remote_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL server instance database flag remote access is set to off",
    "Policy Description": "This policy identifies GCP SQL server instances for which database flag remote access is not set to off. The remote access option controls the execution of stored procedures from local or remote servers on which instances of SQL Server are running. 'Remote access' functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target. It is recommended to set the remote access database flag for SQL Server instance to off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}



#
# PR-GCP-CLD-PSQL-008
#

default storage_psql_log_min_duration_statement = null

gc_issue["storage_psql_log_min_duration_statement"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_min_duration_statement"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_min_duration_statement"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_min_duration_statement"); input.settings.databaseFlags[j].value != -1; c:=1 ]) != 0
}

storage_psql_log_min_duration_statement {
    not gc_issue["storage_psql_log_min_duration_statement"]
}

storage_psql_log_min_duration_statement = false {
    gc_issue["storage_psql_log_min_duration_statement"]
}

storage_psql_log_min_duration_statement_err = "Ensure GCP PostgreSQL instance database flag log_min_duration_statement is set to -1" {
    gc_issue["storage_psql_log_min_duration_statement"]
}

storage_psql_log_min_duration_statement_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_min_duration_statement is set to -1",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_min_duration_statement is not set to -1. The log_min_duration_statement flag defines the minimum amount of execution time of a statement in milliseconds where the total duration of the statement is logged. Logging SQL statements may include sensitive information that should not be recorded in logs. So it is recommended to set  log_min_duration_statement flag value to -1 so that execution statements logging will be disabled.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-011
#

default storage_sql_user_connection = null
issued_ip = ["0.0.0.0/0", "::/0"]

gc_issue["storage_sql_user_connection"] {
    lower(input.state) == "runnable"
    lower(input.databaseVersion) == "sqlserver"
    count([c| contains(lower(input.settings.databaseFlags[_].name), "user connections"); c:=1 ]) == 0
}

storage_sql_user_connection {
    not gc_issue["storage_sql_user_connection"]
}

storage_sql_user_connection = false {
    gc_issue["storage_sql_user_connection"]
}

storage_sql_user_connection_err = "Ensure GCP SQL server instance database flag user connections is set" {
    gc_issue["storage_sql_user_connection"]
}

storage_sql_user_connection_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL server instance database flag user connections is set",
    "Policy Description": "This policy identifies GCP SQL server instances where the database flag 'user connections' is not set. The user connections option specifies the maximum number of simultaneous user connections (value varies in range 10-32,767) that are allowed on an instance of SQL Server. The default is 0, which means that the maximum (32,767) user connections are allowed. It is recommended to set database flag user connections for SQL Server instance according to organization-defined value.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-SQL-012
#

default storage_sql_user_option = null
issued_ip = ["0.0.0.0/0", "::/0"]

gc_issue["storage_sql_user_option"] {
    lower(input.state) == "runnable"
    lower(input.databaseVersion) == "sqlserver"
    count([c| contains(lower(input.settings.databaseFlags[_].name), "user options"); c:=1 ]) != 0
}

storage_sql_user_option {
    not gc_issue["storage_sql_user_option"]
}

storage_sql_user_option = false {
    gc_issue["storage_sql_user_option"]
}

storage_sql_user_option_err = "Ensure GCP SQL server instance database flag user options is not set" {
    gc_issue["storage_sql_user_option"]
}

storage_sql_user_option_metadata := {
    "Policy Code": "PR-GCP-CLD-SQL-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP SQL server instance database flag user options is not set",
    "Policy Description": "This policy identifies GCP SQL server instances fo which database flag user options is set. The user options option specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. A user can override these defaults by using the SET statement. It is recommended that, user options database flag for SQL Server instance should not be configured.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-001
#

default storage_psql_log_connections = null

gc_issue["storage_psql_log_connections"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_connections"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_connections"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_connections"); contains(lower(input.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_connections {
    not gc_issue["storage_psql_log_connections"]
}

storage_psql_log_connections = false {
    gc_issue["storage_psql_log_connections"]
}

storage_psql_log_connections_err = "Ensure GCP PostgreSQL instance database flag log_connections is enabled" {
    gc_issue["storage_psql_log_connections"]
}

storage_psql_log_connections_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_connections is enabled",
    "Policy Description": "This policy identifies PostgreSQL type SQL instances for which the log_connections database flag is disabled. PostgreSQL does not log attempted connections by default. Enabling the log_connections setting will create log entries for each attempted connection as well as successful completion of client authentication which can be useful in troubleshooting issues and to determine any unusual connection attempts to the server.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-009
#

default storage_psql_log_min_messages = null

gc_issue["storage_psql_log_min_messages"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_min_messages"); c:=1 ]) == 0
}

storage_psql_log_min_messages {
    not gc_issue["storage_psql_log_min_messages"]
}

storage_psql_log_min_messages = false {
    gc_issue["storage_psql_log_min_messages"]
}

storage_psql_log_min_messages_err = "Ensure GCP PostgreSQL instance database flag log_min_messages is set" {
    gc_issue["storage_psql_log_min_messages"]
}

storage_psql_log_min_messages_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_min_messages is set",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_min_messages is not set. The log_min_messages flag controls which message levels are written to the server log, valid values are DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC. Each level includes all the levels that follow it. log_min_messages flag value changes should only be made in accordance with the organization's logging policy. Auditing helps in troubleshooting operational problems and also permits forensic analysis.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-010
#

default storage_psql_log_parser_stats = null

gc_issue["storage_psql_log_parser_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_parser_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_parser_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_parser_stats"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_parser_stats {
    not gc_issue["storage_psql_log_parser_stats"]
}

storage_psql_log_parser_stats = false {
    gc_issue["storage_psql_log_parser_stats"]
}

storage_psql_log_parser_stats_err = "Ensure GCP PostgreSQL instance database flag log_parser_stats is set to off" {
    gc_issue["storage_psql_log_parser_stats"]
}

storage_psql_log_parser_stats_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_parser_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_parser_stats is not set to off. The PostgreSQL planner/optimizer is responsible to parse and verify the syntax of each query received by the server. The log_parser_stats flag enables a crude profiling method for logging parser performance statistics. Even though it can be useful for troubleshooting, it may increase the number of logs significantly and have performance overhead. It is recommended to set log_parser_stats as off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-002
#

default storage_psql_log_disconnections = null

gc_issue["storage_psql_log_disconnections"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_disconnections"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_disconnections"] {
    lower(input.state) == "running"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_disconnections"); contains(lower(input.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_disconnections {
    not gc_issue["storage_psql_log_disconnections"]
}

storage_psql_log_disconnections = false {
    gc_issue["storage_psql_log_disconnections"]
}

storage_psql_log_disconnections_err = "Ensure GCP PostgreSQL instance database flag log_disconnections is enabled" {
    gc_issue["storage_psql_log_disconnections"]
}

storage_psql_log_disconnections_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_disconnections is enabled",
    "Policy Description": "This policy identifies PostgreSQL type SQL instances for which the log_disconnections database flag is disabled. Enabling the log_disconnections setting will create log entries at the end of each session which can be useful in troubleshooting issues and determine any unusual activity across a time period.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-011
#

default storage_psql_log_planner_stats = null

gc_issue["storage_psql_log_planner_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_planner_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_planner_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_planner_stats"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_planner_stats {
    not gc_issue["storage_psql_log_planner_stats"]
}

storage_psql_log_planner_stats = false {
    gc_issue["storage_psql_log_planner_stats"]
}

storage_psql_log_planner_stats_err = "Ensure GCP PostgreSQL instance database flag log_planner_stats is set to off" {
    gc_issue["storage_psql_log_planner_stats"]
}

storage_psql_log_planner_stats_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_planner_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_planner_stats is not set to off. The PostgreSQL planner/optimizer is responsible to create an optimal execution plan for each query. The log_planner_stats flag controls the inclusion of PostgreSQL planner performance statistics in the PostgreSQL logs for each query. This can be useful for troubleshooting but may increase the number of logs significantly and have performance overhead. It is recommended to set log_planner_stats off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-003
#

default storage_psql_log_duration = null

gc_issue["storage_psql_log_duration"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_duration"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_duration"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_duration"); contains(lower(input.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_duration {
    not gc_issue["storage_psql_log_duration"]
}

storage_psql_log_duration = false {
    gc_issue["storage_psql_log_duration"]
}

storage_psql_log_duration_err = "Ensure GCP PostgreSQL instance database flag log_duration is set to on" {
    gc_issue["storage_psql_log_duration"]
}

storage_psql_log_duration_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_duration is set to on",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_duration is not set to on. Enabling the log_duration setting causes the duration of each completed statement to be logged. Monitoring the time taken to execute the queries can be crucial in identifying any resource-hogging queries and assessing the performance of the server. Further steps such as load balancing and the use of optimized queries can be taken to ensure the performance and stability of the server. It is recommended to set log_duration as on.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-CLD-PSQL-012
#

default storage_psql_log_statement = null

storage_psql_log_statement_issue_values = ["all", "none"]

gc_issue["storage_psql_log_statement"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_statement"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_statement"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_statement"); contains(lower(input.settings.databaseFlags[j].value), storage_psql_log_statement_issue_values[_]); c:=1 ]) != 0
}

storage_psql_log_statement {
    not gc_issue["storage_psql_log_statement"]
}

storage_psql_log_statement = false {
    gc_issue["storage_psql_log_statement"]
}

storage_psql_log_statement_err = "Ensure GCP PostgreSQL instance database flag log_statement is set appropriately" {
    gc_issue["storage_psql_log_statement"]
}

storage_psql_log_statement_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_statement is set appropriately",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_statement is not set appropriately. If log_statement is not set to a correct value may lead to too many statements or too few statements. Setting log_statement to align with your organization's security and logging policies facilitates later auditing and review of database activities. It is recommended to choose an appropriate value (ddl or mod) for the flag log_statement.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}

#
# PR-GCP-CLD-PSQL-004
#

default storage_psql_log_error_verbosity = null

gc_issue["storage_psql_log_error_verbosity"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_error_verbosity"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_error_verbosity"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_error_verbosity"); contains(lower(input.settings.databaseFlags[j].value), "verbose"); c:=1 ]) != 0
}

storage_psql_log_error_verbosity {
    not gc_issue["storage_psql_log_error_verbosity"]
}

storage_psql_log_error_verbosity = false {
    gc_issue["storage_psql_log_error_verbosity"]
}

storage_psql_log_error_verbosity_err = "Ensure GCP PostgreSQL instance database flag log_error_verbosity is set to default or stricter" {
    gc_issue["storage_psql_log_error_verbosity"]
}

storage_psql_log_error_verbosity_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_error_verbosity is set to default or stricter",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_error_verbosity is not set to default. The flag log_error_verbosity controls the amount of detail written in the server log for each message that is logged. Valid values are TERSE, DEFAULT, and VERBOSE. It is recommended to set log_error_verbosity to default or terse.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-013
#

default storage_psql_log_statement_stats = null

gc_issue["storage_psql_log_statement_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_statement_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_statement_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_statement_stats"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_statement_stats {
    not gc_issue["storage_psql_log_statement_stats"]
}

storage_psql_log_statement_stats = false {
    gc_issue["storage_psql_log_statement_stats"]
}

storage_psql_log_statement_stats_err = "Ensure GCP PostgreSQL instance database flag log_statement_stats is set to off" {
    gc_issue["storage_psql_log_statement_stats"]
}

storage_psql_log_statement_stats_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_statement_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_statement_stats is not set to off. The PostgreSQL planner/optimizer is responsible to create an optimal execution plan for each query. The log_planner_stats flag controls the inclusion of PostgreSQL planner performance statistics in the PostgreSQL logs for each query. This can be useful for troubleshooting but may increase the number of logs significantly and have performance overhead. It is recommended to set log_planner_stats off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-005
#

default storage_psql_log_executor_stats = null

gc_issue["storage_psql_log_executor_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_executor_stats"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_executor_stats"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_executor_stats"); contains(lower(input.settings.databaseFlags[j].value), "on"); c:=1 ]) != 0
}

storage_psql_log_executor_stats {
    not gc_issue["storage_psql_log_executor_stats"]
}

storage_psql_log_executor_stats = false {
    gc_issue["storage_psql_log_executor_stats"]
}

storage_psql_log_executor_stats_err = "Ensure GCP PostgreSQL instance database flag log_executor_stats is set to off" {
    gc_issue["storage_psql_log_executor_stats"]
}

storage_psql_log_executor_stats_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_executor_stats is set to off",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_executor_stats is not set to off. The log_executor_stats flag enables a crude profiling method for logging PostgreSQL executor performance statistics. Even though it can be useful for troubleshooting, it may increase the number of logs significantly and have performance overhead. It is recommended to set log_executor_stats off.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-014
#

default storage_psql_log_temp_files = null

gc_issue["storage_psql_log_temp_files"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_temp_files"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_temp_files"] {
    lower(input.state) == "runnable"
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_temp_files"); input.settings.databaseFlags[j].value != 0; c:=1 ]) != 0
}

storage_psql_log_temp_files {
    not gc_issue["storage_psql_log_temp_files"]
}

storage_psql_log_temp_files = false {
    gc_issue["storage_psql_log_temp_files"]
}

storage_psql_log_temp_files_err = "Ensure GCP PostgreSQL instance database flag log_temp_files is set to 0" {
    gc_issue["storage_psql_log_temp_files"]
}

storage_psql_log_temp_files_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance database flag log_temp_files is set to 0",
    "Policy Description": "This policy identifies PostgreSQL database instances in which database flag log_temp_files is not set to 0. The log_temp_files flag controls the logging of names and size of temporary files. Configuring log_temp_files to 0 causes all temporary file information to be logged, while positive values log only files whose size is greater than or equal to the specified number of kilobytes. A value of -1 disables temporary file information logging. If all temporary files are not logged, it may be more difficult to identify potential performance issues that may be either poor application coding or deliberate resource starvation attempts.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}


#
# PR-GCP-CLD-PSQL-015
#

default storage_psql_log_checkpoints = null


gc_issue["storage_psql_log_checkpoints"] {
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[_].name), "log_checkpoints"); c:=1 ]) == 0
}

gc_issue["storage_psql_log_checkpoints"] {
    contains(lower(input.databaseVersion), "postgres")
    count([c| contains(lower(input.settings.databaseFlags[j].name), "log_checkpoints"); contains(lower(input.settings.databaseFlags[j].value), "off"); c:=1 ]) != 0
}

storage_psql_log_checkpoints {
    not gc_issue["storage_psql_log_checkpoints"]
}

storage_psql_log_checkpoints = false {
    gc_issue["storage_psql_log_checkpoints"]
}

storage_psql_log_checkpoints_err = "Ensure GCP PostgreSQL instance with log_checkpoints database flag is enabled" {
    gc_issue["storage_psql_log_checkpoints"]
}

storage_psql_log_checkpoints_metadata := {
    "Policy Code": "PR-GCP-CLD-PSQL-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP PostgreSQL instance with log_checkpoints database flag is enabled",
    "Policy Description": "This policy identifies PostgreSQL instances in which log_checkpoints database flag is not set. Enabling the log_checkpoints database flag would enable logging of checkpoints and restart points to the server log.",
    "Resource Type": "sqladmin.v1beta4.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances"
}
