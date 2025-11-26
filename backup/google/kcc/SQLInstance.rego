package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/sql/sqlinstance

#
# AUTO_BACKUP_DISABLED
# PR-GCP-0056-KCC

default auto_backup_disabled = null

gc_issue["auto_backup_disabled"] {
    lower(input.kind) == "sqlinstance"
    not input.spec.settings.backupConfiguration.enabled
}

auto_backup_disabled {
    lower(input.kind) == "sqlinstance"
    not gc_issue["auto_backup_disabled"]
}

auto_backup_disabled = false {
    gc_issue["auto_backup_disabled"]
}

auto_backup_disabled_err = "A Cloud SQL database doesn't have automatic backups enabled." {
    gc_issue["auto_backup_disabled"]
}

auto_backup_disabled_metadata := {
    "Policy Code": "AUTO_BACKUP_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Auto Backup Disabled",
    "Policy Description": "A Cloud SQL database doesn't have automatic backups enabled.",
    "Resource Type": "SQLInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/sql/sqlinstance"
}

#
# SSL_NOT_ENFORCED
# PR-GCP-0057-KCC

default ssl_not_enforced = null

gc_issue["ssl_not_enforced"] {
    lower(input.kind) == "sqlinstance"
    not input.spec.settings.ipConfiguration.requireSsl
}

ssl_not_enforced {
    lower(input.kind) == "sqlinstance"
    not gc_issue["ssl_not_enforced"]
}

ssl_not_enforced = false {
    gc_issue["ssl_not_enforced"]
}

ssl_not_enforced_err = "A Cloud SQL database instance doesn't require all incoming connections to use SSL." {
    gc_issue["ssl_not_enforced"]
}

ssl_not_enforced_metadata := {
    "Policy Code": "SSL_NOT_ENFORCED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "SSL Not Enforced",
    "Policy Description": "A Cloud SQL database instance doesn't require all incoming connections to use SSL.",
    "Resource Type": "SQLInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/sql/sqlinstance"
}

#
# SQL_NO_ROOT_PASSWORD
# PR-GCP-0058-KCC

default sql_no_root_password = null

gc_issue["sql_no_root_password"] {
    lower(input.kind) == "sqlinstance"
    not input.spec.rootPassword.value
}

gc_issue["sql_no_root_password"] {
    lower(input.kind) == "sqlinstance"
    input.spec.rootPassword.value == ""
}

sql_no_root_password {
    lower(input.kind) == "sqlinstance"
    not gc_issue["sql_no_root_password"]
}

sql_no_root_password = false {
    gc_issue["sql_no_root_password"]
}

sql_no_root_password_err = "A Cloud SQL database doesn't have a password configured for the root account." {
    gc_issue["sql_no_root_password"]
}

sql_no_root_password_metadata := {
    "Policy Code": "SQL_NO_ROOT_PASSWORD",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Sql No Root Password",
    "Policy Description": "A Cloud SQL database doesn't have a password configured for the root account.",
    "Resource Type": "SQLInstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/sql/sqlinstance"
}
