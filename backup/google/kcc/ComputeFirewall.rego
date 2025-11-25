package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall

#
# EGRESS_DENY_RULE_NOT_SET
# PR-GCP-0002-KCC

default egress_deny_rule_not_set = null

gc_issue["egress_deny_rule_not_set"] {
    lower(input.kind) == "computefirewall"
    not input.spec.deny
}

gc_issue["egress_deny_rule_not_set"] {
    lower(input.kind) == "computefirewall"
    count([
        c | lower(input.spec.deny[_].protocol) == "all";
        input.spec.deny[_].destinationRanges[_] == "0.0.0.0/0"; c := 1
    ]) == 0
}

egress_deny_rule_not_set {
    lower(input.kind) == "computefirewall"
    not gc_issue["egress_deny_rule_not_set"]
}

egress_deny_rule_not_set = false {
    gc_issue["egress_deny_rule_not_set"]
}

egress_deny_rule_not_set_err = "An egress deny rule is not set on a firewall." {
    gc_issue["egress_deny_rule_not_set"]
}

egress_deny_rule_not_set_metadata := {
    "Policy Code": "EGRESS_DENY_RULE_NOT_SET",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Egress Deny Rule Not Set",
    "Policy Description": "An egress deny rule is not set on a firewall.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# FIREWALL_RULE_LOGGING_DISABLED
# PR-GCP-0003-KCC

default firewall_rule_logging_disabled = null

gc_issue["firewall_rule_logging_disabled"] {
    lower(input.kind) == "computefirewall"
    not input.spec.logConfig
}

firewall_rule_logging_disabled {
    lower(input.kind) == "computefirewall"
    not gc_issue["firewall_rule_logging_disabled"]
}

firewall_rule_logging_disabled = false {
    gc_issue["firewall_rule_logging_disabled"]
}

firewall_rule_logging_disabled_err = "Firewall rule logging is disabled." {
    gc_issue["firewall_rule_logging_disabled"]
}

firewall_rule_logging_disabled_metadata := {
    "Policy Code": "FIREWALL_RULE_LOGGING_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Firewall Rule Logging Disabled",
    "Policy Description": "Firewall rule logging is disabled.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_CASSANDRA_PORT
# PR-GCP-0004-KCC

default open_cassandra_port = null

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 7000
    to_number(port_range[1]) >= 7001
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 7199
    to_number(port_range[1]) >= 7199
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 8888
    to_number(port_range[1]) >= 8888
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 9042
    to_number(port_range[1]) >= 9042
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 9160
    to_number(port_range[1]) >= 9160
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 61620
    to_number(port_range[1]) >= 61621
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 7000
    to_number(port) >= 7001
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 7199
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 8888
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 9042
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 9160
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 61620
    to_number(port) >= 61621
}

open_cassandra_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_cassandra_port"]
}

open_cassandra_port = false {
    gc_issue["open_cassandra_port"]
}

open_cassandra_port_err = "A firewall is configured to have an open CASSANDRA port that allows generic access." {
    gc_issue["open_cassandra_port"]
}

open_cassandra_port_metadata := {
    "Policy Code": "OPEN_CASSANDRA_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "OPEN CASSANDRA PORT",
    "Policy Description": "A firewall is configured to have an open CASSANDRA port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_CISCOSECURE_WEBSM_PORT
# PR-GCP-0005-KCC

default open_ciscosecure_websm_port = null

gc_issue["open_ciscosecure_websm_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 9090
    to_number(port_range[1]) >= 9090
}

gc_issue["open_ciscosecure_websm_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 9090
}

open_ciscosecure_websm_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_ciscosecure_websm_port"]
}

open_ciscosecure_websm_port = false {
    gc_issue["open_ciscosecure_websm_port"]
}

open_ciscosecure_websm_port_err = "A firewall is configured to have an open CISCOSECURE_WEBSM port that allows generic access." {
    gc_issue["open_ciscosecure_websm_port"]
}

open_ciscosecure_websm_port_metadata := {
    "Policy Code": "OPEN_CISCOSECURE_WEBSM_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open Ciscosecure Websm Port",
    "Policy Description": "A firewall is configured to have an open CISCOSECURE_WEBSM port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_DIRECTORY_SERVICES_PORT
# PR-GCP-0006-KCC

default open_directory_services_port = null

gc_issue["open_directory_services_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 445
    to_number(port_range[1]) >= 445
}

gc_issue["open_directory_services_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 445
}

open_directory_services_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_directory_services_port"]
}

open_directory_services_port = false {
    gc_issue["open_directory_services_port"]
}

open_directory_services_port_err = "A firewall is configured to have an open DIRECTORY_SERVICES port that allows generic access." {
    gc_issue["open_directory_services_port"]
}

open_directory_services_port_metadata := {
    "Policy Code": "OPEN_DIRECTORY_SERVICES_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open Directory Services Port",
    "Policy Description": "A firewall is configured to have an open DIRECTORY_SERVICES port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_DNS_PORT
# PR-GCP-0007-KCC

default open_dns_port = null

gc_issue["open_dns_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 53
    to_number(port_range[1]) >= 53
}

gc_issue["open_dns_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 53
}

open_dns_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_dns_port"]
}

open_dns_port = false {
    gc_issue["open_dns_port"]
}

open_dns_port_err = "A firewall is configured to have an open DNS port that allows generic access." {
    gc_issue["open_dns_port"]
}

open_dns_port_metadata := {
    "Policy Code": "OPEN_DNS_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open DNS Port",
    "Policy Description": "A firewall is configured to have an open DNS port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_ELASTICSEARCH_PORT
# PR-GCP-0008-KCC

default open_elasticsearch_port = null

gc_issue["open_elasticsearch_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 9200
    to_number(port_range[1]) >= 9200
}

gc_issue["open_elasticsearch_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 9300
    to_number(port_range[1]) >= 9300
}

gc_issue["open_elasticsearch_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 9200
}

gc_issue["open_elasticsearch_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 9300
}

open_elasticsearch_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_elasticsearch_port"]
}

open_elasticsearch_port = false {
    gc_issue["open_elasticsearch_port"]
}

open_elasticsearch_port_err = "A firewall is configured to have an open ELASTICSEARCH port that allows generic access." {
    gc_issue["open_elasticsearch_port"]
}

open_elasticsearch_port_metadata := {
    "Policy Code": "OPEN_ELASTICSEARCH_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open DNS Port",
    "Policy Description": "A firewall is configured to have an open ELASTICSEARCH port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_FIREWALL
# PR-GCP-0009-KCC

default open_firewall = null

gc_issue["open_firewall"] {
    lower(input.kind) == "computefirewall"
    count([
        c | lower(input.spec.allow[_].protocol) == "all";
        input.spec.allow[_].sourceRanges[_] == "0.0.0.0/0"; c := 1
    ]) == 0
}

open_firewall {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_firewall"]
}

open_firewall = false {
    gc_issue["open_firewall"]
}

open_firewall_err = "A firewall is configured to be open to public access." {
    gc_issue["open_firewall"]
}

open_firewall_metadata := {
    "Policy Code": "OPEN_FIREWALL",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open Firewall",
    "Policy Description": "A firewall is configured to be open to public access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_FTP_PORT
# PR-GCP-0010-KCC

default open_ftp_port = null

gc_issue["open_ftp_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 21
    to_number(port_range[1]) >= 21
}

gc_issue["open_ftp_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 21
}

open_ftp_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_ftp_port"]
}

open_ftp_port = false {
    gc_issue["open_ftp_port"]
}

open_ftp_port_err = "A firewall is configured to have an open FTP port that allows generic access." {
    gc_issue["open_ftp_port"]
}

open_ftp_port_metadata := {
    "Policy Code": "OPEN_FTP_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open FTP Port",
    "Policy Description": "A firewall is configured to have an open FTP port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_HTTP_PORT
# PR-GCP-0011-KCC

default open_http_port = null

gc_issue["open_http_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 80
    to_number(port_range[1]) >= 80
}

gc_issue["open_http_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 80
}

open_http_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_http_port"]
}

open_http_port = false {
    gc_issue["open_http_port"]
}

open_http_port_err = "A firewall is configured to have an open HTTP port that allows generic access." {
    gc_issue["open_http_port"]
}

open_http_port_metadata := {
    "Policy Code": "OPEN_HTTP_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open HTTP Port",
    "Policy Description": "A firewall is configured to have an open HTTP port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_LDAP_PORT
# PR-GCP-0012-KCC

default open_ldap_port = null

gc_issue["open_ldap_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 389
    to_number(port_range[1]) >= 389
}

gc_issue["open_ldap_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 636
    to_number(port_range[1]) >= 636
}

gc_issue["open_ldap_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 389
}

gc_issue["open_ldap_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 636
}

open_ldap_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_ldap_port"]
}

open_ldap_port = false {
    gc_issue["open_ldap_port"]
}

open_ldap_port_err = "A firewall is configured to have an open LDAP port that allows generic access." {
    gc_issue["open_ldap_port"]
}

open_ldap_port_metadata := {
    "Policy Code": "OPEN_LDAP_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open LDAP Port",
    "Policy Description": "A firewall is configured to have an open LDAP port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_MEMCACHED_PORT
# PR-GCP-0013-KCC

default open_memcached_port = null

gc_issue["open_memcached_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 11211
    to_number(port_range[1]) >= 11211
}

gc_issue["open_memcached_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 11214
    to_number(port_range[1]) >= 11215
}

gc_issue["open_memcached_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 11211
}

gc_issue["open_memcached_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 11214
    to_number(port) >= 11215
}

open_memcached_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_memcached_port"]
}

open_memcached_port = false {
    gc_issue["open_memcached_port"]
}

open_memcached_port_err = "A firewall is configured to have an open MEMCACHED port that allows generic access." {
    gc_issue["open_memcached_port"]
}

open_memcached_port_metadata := {
    "Policy Code": "OPEN_MEMCACHED_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open MEMCACHED Port",
    "Policy Description": "A firewall is configured to have an open MEMCACHED port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_MONGODB_PORT
# PR-GCP-0014-KCC

default open_mongodb_port = null

gc_issue["open_mongodb_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 27017
    to_number(port_range[1]) >= 27019
}

gc_issue["open_mongodb_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 27017
    to_number(port) >= 27019
}

open_mongodb_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_mongodb_port"]
}

open_mongodb_port = false {
    gc_issue["open_mongodb_port"]
}

open_mongodb_port_err = "A firewall is configured to have an open MONGODB port that allows generic access." {
    gc_issue["open_mongodb_port"]
}

open_mongodb_port_metadata := {
    "Policy Code": "OPEN_MONGODB_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open MONGODB Port",
    "Policy Description": "A firewall is configured to have an open MONGODB port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_MYSQL_PORT
# PR-GCP-0015-KCC

default open_mysql_port = null

gc_issue["open_mysql_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3306
    to_number(port_range[1]) >= 3306
}

gc_issue["open_mysql_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 3306
}

open_mysql_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_mysql_port"]
}

open_mysql_port = false {
    gc_issue["open_mysql_port"]
}

open_mysql_port_err = "A firewall is configured to have an open MySQL port that allows generic access." {
    gc_issue["open_mysql_port"]
}

open_mysql_port_metadata := {
    "Policy Code": "OPEN_MYSQL_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open MySQL Port",
    "Policy Description": "A firewall is configured to have an open MySQL port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_NETBIOS_PORT
# PR-GCP-0016-KCC

default open_netbios_port = null

gc_issue["open_netbios_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 137
    to_number(port_range[1]) >= 139
}

gc_issue["open_netbios_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 137
    to_number(port) >= 139
}

open_netbios_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_netbios_port"]
}

open_netbios_port = false {
    gc_issue["open_netbios_port"]
}

open_netbios_port_err = "A firewall is configured to have an open NETBIOS port that allows generic access." {
    gc_issue["open_netbios_port"]
}

open_netbios_port_metadata := {
    "Policy Code": "OPEN_NETBIOS_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open NETBIOS Port",
    "Policy Description": "A firewall is configured to have an open NETBIOS port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_ORACLEDB_PORT
# PR-GCP-0017-KCC

default open_oracledb_port = null

gc_issue["open_oracledb_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 1521
    to_number(port_range[1]) >= 1521
}

gc_issue["open_oracledb_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 2483
    to_number(port_range[1]) >= 2484
}

gc_issue["open_oracledb_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 1521
}

gc_issue["open_oracledb_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 2483
    to_number(port) >= 2484
}

open_oracledb_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_oracledb_port"]
}

open_oracledb_port = false {
    gc_issue["open_oracledb_port"]
}

open_oracledb_port_err = "A firewall is configured to have an open ORACLEDB port that allows generic access." {
    gc_issue["open_oracledb_port"]
}

open_oracledb_port_metadata := {
    "Policy Code": "OPEN_ORACLEDB_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open ORACLEDB Port",
    "Policy Description": "A firewall is configured to have an open ORACLEDB port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_POP3_PORT
# PR-GCP-0018-KCC

default open_pop3_port = null

gc_issue["open_pop3_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 110
    to_number(port_range[1]) >= 110
}

gc_issue["open_pop3_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 110
}

open_pop3_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_pop3_port"]
}

open_pop3_port = false {
    gc_issue["open_pop3_port"]
}

open_pop3_port_err = "A firewall is configured to have an open POP3 port that allows generic access." {
    gc_issue["open_pop3_port"]
}

open_pop3_port_metadata := {
    "Policy Code": "OPEN_POP3_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open POP3 Port",
    "Policy Description": "A firewall is configured to have an open POP3 port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_POSTGRESQL_PORT
# PR-GCP-0019-KCC

default open_postgresql_port = null

gc_issue["open_postgresql_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 5432
    to_number(port_range[1]) >= 5432
}

gc_issue["open_postgresql_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 5432
}

open_postgresql_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_postgresql_port"]
}

open_postgresql_port = false {
    gc_issue["open_postgresql_port"]
}

open_postgresql_port_err = "A firewall is configured to have an open POSTGRESQL port that allows generic access." {
    gc_issue["open_postgresql_port"]
}

open_postgresql_port_metadata := {
    "Policy Code": "OPEN_POSTGRESQL_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open POSTGRESQL Port",
    "Policy Description": "A firewall is configured to have an open POSTGRESQL port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_RDP_PORT
# PR-GCP-0020-KCC

default open_rdp_port = null

gc_issue["open_rdp_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3389
    to_number(port_range[1]) >= 3389
}

gc_issue["open_rdp_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|udp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 3389
}

open_rdp_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_rdp_port"]
}

open_rdp_port = false {
    gc_issue["open_rdp_port"]
}

open_rdp_port_err = "A firewall is configured to have an open RDP port that allows generic access." {
    gc_issue["open_rdp_port"]
}

open_rdp_port_metadata := {
    "Policy Code": "OPEN_RDP_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open RDP Port",
    "Policy Description": "A firewall is configured to have an open RDP port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_REDIS_PORT
# PR-GCP-0021-KCC

default open_redis_port = null

gc_issue["open_redis_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 6379
    to_number(port_range[1]) >= 6379
}

gc_issue["open_redis_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 6379
}

open_redis_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_redis_port"]
}

open_redis_port = false {
    gc_issue["open_redis_port"]
}

open_redis_port_err = "A firewall is configured to have an open REDIS port that allows generic access." {
    gc_issue["open_redis_port"]
}

open_redis_port_metadata := {
    "Policy Code": "OPEN_REDIS_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open REDIS Port",
    "Policy Description": "A firewall is configured to have an open REDIS port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_SMTP_PORT
# PR-GCP-0022-KCC

default open_smtp_port = null

gc_issue["open_smtp_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 25
    to_number(port_range[1]) >= 25
}

gc_issue["open_smtp_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 25
}

open_smtp_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_smtp_port"]
}

open_smtp_port = false {
    gc_issue["open_smtp_port"]
}

open_smtp_port_err = "A firewall is configured to have an open SMTP port that allows generic access." {
    gc_issue["open_smtp_port"]
}

open_smtp_port_metadata := {
    "Policy Code": "OPEN_SMTP_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open SMTP Port",
    "Policy Description": "A firewall is configured to have an open SMTP port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_SSH_PORT
# PR-GCP-0023-KCC

default open_ssh_port = null

gc_issue["open_ssh_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|sctp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 22
    to_number(port_range[1]) >= 22
}

gc_issue["open_ssh_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|sctp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 22
}

open_ssh_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_ssh_port"]
}

open_ssh_port = false {
    gc_issue["open_ssh_port"]
}

open_ssh_port_err = "A firewall is configured to have an open SSH port that allows generic access." {
    gc_issue["open_ssh_port"]
}

open_ssh_port_metadata := {
    "Policy Code": "OPEN_SSH_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open SSH Port",
    "Policy Description": "A firewall is configured to have an open SSH port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_TELNET_PORT
# PR-GCP-0024-KCC

default open_telnet_port = null

gc_issue["open_telnet_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 23
    to_number(port_range[1]) >= 23
}

gc_issue["open_telnet_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    regex.match("^(tcp|all)$", lower(allowed.protocol))
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 23
}

open_telnet_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_telnet_port"]
}

open_telnet_port = false {
    gc_issue["open_telnet_port"]
}

open_telnet_port_err = "A firewall is configured to have an open TELNET port that allows generic access." {
    gc_issue["open_telnet_port"]
}

open_telnet_port_metadata := {
    "Policy Code": "OPEN_TELNET_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Open TELNET Port",
    "Policy Description": "A firewall is configured to have an open TELNET port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}
