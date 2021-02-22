package rule

sql_database_issue["invalid_sql_minimal_tls_version"] {
    input.type == "Microsoft.Sql/servers"
    input.properties.minimalTlsVersion != "1.2"
}

default sql_server_rulepass = null

sql_server_rulepass = true {
    not sql_database_issue["invalid_sql_minimal_tls_version"]
}

sql_server_rulepass = false {
    sql_database_issue["invalid_sql_minimal_tls_version"]
}

sql_server_rulepass_err = "Azure SQL Server has configured TLS version lower then 1.2" {
    sql_database_issue["invalid_sql_minimal_tls_version"]
}


sql_database_issue["invalid_sql_instance_tls_version"] {
    input.type == "Microsoft.Sql/managedInstances"
    input.properties.minimalTlsVersion != "1.2"
}

default sql_instance_rulepass = null

sql_instance_rulepass = true {
    not sql_database_issue["invalid_sql_instance_tls_version"]
}

sql_instance_rulepass = false {
    sql_database_issue["invalid_sql_instance_tls_version"]
}

sql_instance_rulepass_err = "Azure SQL Managed Instance has configured TLS version lower then 1.2" {
    sql_database_issue["invalid_sql_instance_tls_version"]
}