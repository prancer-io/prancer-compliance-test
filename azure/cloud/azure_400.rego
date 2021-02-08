package rule

sql_database_issue["invalid_sql_minimal_tls_version"] {
    lower(input.type) == "microsoft.sql/servers"
    input.properties.minimalTlsVersion != "1.2"
}

default rulepass = null

rulepass = true {
    not sql_database_issue["invalid_sql_minimal_tls_version"]
}

rulepass = false {
    sql_database_issue["invalid_sql_minimal_tls_version"]
}

rulepass_err = "Azure SQL Server has configured TLS version lower then 1.2" {
    sql_database_issue["invalid_sql_minimal_tls_version"]
}
