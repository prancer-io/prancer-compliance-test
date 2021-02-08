package rule

sql_database_issue["invalid_sql_instance_tls_version"] {
    lower(input.type) == "microsoft.sql/managedinstances"
    input.properties.minimalTlsVersion != "1.2"
}

default rulepass = null

rulepass = true {
    not sql_database_issue["invalid_sql_instance_tls_version"]
}

rulepass = false {
    sql_database_issue["invalid_sql_instance_tls_version"]
}

rulepass_err = "Azure SQL Managed Instance has configured TLS version lower then 1.2" {
    sql_database_issue["invalid_sql_instance_tls_version"]
}