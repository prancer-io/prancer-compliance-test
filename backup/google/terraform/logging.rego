package rule

#
# PR-GCP-TRF-LOG-001
#

default logging_audit_config = null

logging_audit_config_contains = ["protopayload.methodname=", "protopayload.methodname ="]

gc_issue["logging_audit_config"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_audit_config_contains[_])
    not contains(lower(resource.properties.filter), "protopayload.methodname!=")
    not contains(lower(resource.properties.filter), "protopayload.methodname !=")
    contains(lower(resource.properties.filter), "setiampolicy")
    contains(lower(resource.properties.filter), "protopayload.servicedata.policydelta.auditconfigdeltas:*")
}

logging_audit_config {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_audit_config"]
}

logging_audit_config = false {
    gc_issue["logging_audit_config"]
}

logging_audit_config_err = "Ensure GCP Log metric filter and alert exists for Audit Configuration Changes" {
    gc_issue["logging_audit_config"]
}

logging_audit_config_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for Audit Configuration Changes",
    "Policy Description": "This policy identifies the GCP accounts which do not have a log metric filter and alert for Audit Configuration Changes. Configuring metric filter and alerts for Audit Configuration Changes ensures recommended state of audit configuration and hence, all the activities in project are audit-able at any point in time.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-TRF-LOG-002
#

default logging_iam_permission_change = null

logging_iam_permission_change_contains_1 = ["resource.type=", "resource.type ="]
logging_iam_permission_change_contains_2 = ["protopayload.methodname=", "protopayload.methodname ="]

gc_issue["logging_iam_permission_change"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_iam_permission_change_contains_1[_])
    not contains(lower(resource.properties.filter), "resource.type!=")
    not contains(lower(resource.properties.filter), "resource.type !=")
    contains(lower(resource.properties.filter), "gcs_bucket")
    contains(lower(resource.properties.filter), logging_iam_permission_change_contains_2[_])
    not contains(lower(resource.properties.filter), "protopayload.methodname!=")
    not contains(lower(resource.properties.filter), "protopayload.methodname !=")
    contains(lower(resource.properties.filter), "storage.setiampermissions")
}

logging_iam_permission_change {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_iam_permission_change"]
}

logging_iam_permission_change = false {
    gc_issue["logging_iam_permission_change"]
}

logging_iam_permission_change_err = "Ensure GCP Log metric filter and alert exists for Cloud Storage IAM permission changes" {
    gc_issue["logging_iam_permission_change"]
}

logging_iam_permission_change_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for Cloud Storage IAM permission changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for Cloud Storage IAM permission changes. Monitoring Cloud Storage IAM permission activities will help in reducing time to detect and correct permissions on sensitive Cloud Storage bucket and objects inside the bucket. It is recommended to create a metric filter and alarm to detect activities related to the Cloud Storage IAM permission.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-TRF-LOG-003
#

default logging_iam_custom_permission_change = null

logging_iam_custom_permission_change_contains_1 = ["resource.type=", "resource.type ="]
logging_iam_custom_permission_change_contains_2 = ["protopayload.methodname=", "protopayload.methodname ="]

gc_issue["logging_iam_custom_permission_change"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_iam_custom_permission_change_contains_1[_])
    not contains(lower(resource.properties.filter), "resource.type!=")
    not contains(lower(resource.properties.filter), "resource.type !=")
    contains(lower(resource.properties.filter), "iam_role")
    contains(lower(resource.properties.filter), logging_iam_custom_permission_change_contains_2[_])
    not contains(lower(resource.properties.filter), "protopayload.methodname!=")
    not contains(lower(resource.properties.filter), "protopayload.methodname !=")
    contains(lower(resource.properties.filter), "google.iam.admin.v1.createrole")
    contains(lower(resource.properties.filter), "google.iam.admin.v1.deleterole")
    contains(lower(resource.properties.filter), "google.iam.admin.v1.updaterole")
}

logging_iam_custom_permission_change {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_iam_custom_permission_change"]
}

logging_iam_custom_permission_change = false {
    gc_issue["logging_iam_custom_permission_change"]
}

logging_iam_custom_permission_change_err = "Ensure GCP Log metric filter and alert does exists for IAM custom role changes" {
    gc_issue["logging_iam_custom_permission_change"]
}

logging_iam_custom_permission_change_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log metric filter and alert does exists for IAM custom role changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for IAM custom role changes. Monitoring role creation, deletion and updating activities will help in identifying over-privileged roles at early stages. It is recommended to create a metric filter and alarm to detect activities related to the creation, deletion and updating of custom IAM Roles.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-TRF-LOG-004
#

default logging_project_ownership = null

logging_project_ownership_contains_1 = ["protopayload.servicename=", "protopayload.servicename ="]
logging_project_ownership_contains_2 = ["protopayload.servicedata.policydelta.bindingdeltas.action=", "protopayload.servicedata.policydelta.bindingdeltas.action ="]
logging_project_ownership_contains_3 = ["protopayload.servicedata.policydelta.bindingdeltas.role=", "protopayload.servicedata.policydelta.bindingdeltas.role ="]

gc_issue["logging_project_ownership"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_project_ownership_contains_1[_])
    not contains(lower(resource.properties.filter), "protopayload.servicename!=")
    not contains(lower(resource.properties.filter), "protopayload.servicename !=")
    contains(lower(resource.properties.filter), "cloudresourcemanager.googleapis.com")
    contains(lower(resource.properties.filter), "projectownership or projectownerinvitee")
    contains(lower(resource.properties.filter), logging_project_ownership_contains_2[_])
    not contains(lower(resource.properties.filter), "protopayload.servicedata.policydelta.bindingdeltas.action!=")
    not contains(lower(resource.properties.filter), "protopayload.servicedata.policydelta.bindingdeltas.action !=")
    contains(lower(resource.properties.filter), logging_project_ownership_contains_3[_])
    not contains(lower(resource.properties.filter), "protopayload.servicedata.policydelta.bindingdeltas.role!=")
    not contains(lower(resource.properties.filter), "protopayload.servicedata.policydelta.bindingdeltas.role !=")
    contains(lower(resource.properties.filter), "remove")
    contains(lower(resource.properties.filter), "add")
    contains(lower(resource.properties.filter), "roles/owner")
}

logging_project_ownership {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_project_ownership"]
}

logging_project_ownership = false {
    gc_issue["logging_project_ownership"]
}

logging_project_ownership_err = "Ensure GCP Log metric filter and alert exists for Project Ownership assignments/changes" {
    gc_issue["logging_project_ownership"]
}

logging_project_ownership_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for Project Ownership assignments/changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for Project Ownership assignments/changes. Project Ownership Having highest level of privileges on a project, to avoid misuse of project resources project ownership assignment/change actions mentioned should be monitored and alerted to concerned recipients.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-TRF-LOG-005
#

default logging_sql_instance = null

logging_sql_instance_contains = ["protopayload.methodname=", "protopayload.methodname ="]

gc_issue["logging_sql_instance"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_sql_instance_contains[_])
    not contains(lower(resource.properties.filter), "protopayload.methodname!=")
    not contains(lower(resource.properties.filter), "protopayload.methodname !=")
    contains(lower(resource.properties.filter), "cloudsql.instances.update")
}

logging_sql_instance {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_sql_instance"]
}

logging_sql_instance = false {
    gc_issue["logging_sql_instance"]
}

logging_sql_instance_err = "Ensure GCP Log metric filter and alert exists for SQL instance configuration changes" {
    gc_issue["logging_sql_instance"]
}

logging_sql_instance_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for SQL instance configuration changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for SQL instance configuration changes. Monitoring SQL instance configuration activities will help in reducing time to detect and correct misconfigurations done on sql server. It is recommended to create a metric filter and alarm to detect activities related to the SQL instance configuration.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-TRF-LOG-006
#

default logging_vpc_firewall = null

logging_vpc_firewall_contains_1 = ["resource.type=", "resource.type ="]
logging_vpc_firewall_contains_2 = ["jsonPayload.event_subtype=", "jsonPayload.event_subtype ="]

gc_issue["logging_vpc_firewall"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_vpc_firewall_contains_1[_])
    not contains(lower(resource.properties.filter), "resource.type!=")
    not contains(lower(resource.properties.filter), "resource.type !=")
    contains(lower(resource.properties.filter), "gce_firewall_rule")
    contains(lower(resource.properties.filter), logging_vpc_firewall_contains_2[_])
    not contains(lower(resource.properties.filter), "jsonPayload.event_subtype!=")
    not contains(lower(resource.properties.filter), "jsonPayload.event_subtype !=")
    contains(lower(resource.properties.filter), "compute.firewalls.patch")
    contains(lower(resource.properties.filter), "compute.firewalls.insert")
}

logging_vpc_firewall {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_vpc_firewall"]
}

logging_vpc_firewall = false {
    gc_issue["logging_vpc_firewall"]
}

logging_vpc_firewall_err = "Ensure GCP Log metric filter and alert exists for VPC Network Firewall rule changes" {
    gc_issue["logging_vpc_firewall"]
}

logging_vpc_firewall_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for VPC Network Firewall rule changes",
    "Policy Description": "This policy identifies the GCP accounts which do not have a log metric filter and alert for VPC Network Firewall rule changes. Monitoring for Create or Update firewall rule events gives insight network access changes and may reduce the time it takes to detect suspicious activity. It is recommended to create a metric filter and alarm to detect VPC Network Firewall rule changes.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-TRF-LOG-007
#

default logging_vpc_network = null

logging_vpc_network_contains_1 = ["resource.type=", "resource.type ="]
logging_vpc_network_contains_2 = ["jsonPayload.event_subtype=", "jsonPayload.event_subtype ="]

gc_issue["logging_vpc_network"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_vpc_network_contains_1[_])
    not contains(lower(resource.properties.filter), "resource.type!=")
    not contains(lower(resource.properties.filter), "resource.type !=")
    contains(lower(resource.properties.filter), "gce_network")
    contains(lower(resource.properties.filter), logging_vpc_network_contains_2[_])
    not contains(lower(resource.properties.filter), "jsonPayload.event_subtype!=")
    not contains(lower(resource.properties.filter), "jsonPayload.event_subtype !=")
    contains(lower(resource.properties.filter), "compute.networks.insert")
    contains(lower(resource.properties.filter), "compute.networks.patch")
    contains(lower(resource.properties.filter), "compute.networks.delete")
    contains(lower(resource.properties.filter), "compute.networks.removePeering")
    contains(lower(resource.properties.filter), "compute.networks.addPeering")
}

logging_vpc_network {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_vpc_network"]
}

logging_vpc_network = false {
    gc_issue["logging_vpc_network"]
}

logging_vpc_network_err = "GCP Log metric filter and alert exists for VPC network changes" {
    gc_issue["logging_vpc_network"]
}

logging_vpc_network_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Log metric filter and alert exists for VPC network changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for VPC network changes. Monitoring network insertion, patching, deletion, removePeering and addPeering activities will help in identifying VPC traffic flow is not getting impacted. It is recommended to create a metric filter and alarm to detect activities related to the insertion, patching, deletion, removePeering and addPeering of VPC network.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-TRF-LOG-008
#

default logging_vpc_route = null

logging_vpc_route_contains_1 = ["resource.type=", "resource.type ="]
logging_vpc_route_contains_2 = ["jsonPayload.event_subtype=", "jsonPayload.event_subtype ="]

gc_issue["logging_vpc_route"] {
    resource := input.resources[i]
    lower(resource.type) == "google_logging_metric"
    not gc_not_issue(resource)
}

gc_not_issue(resource){
    contains(lower(resource.properties.filter), logging_vpc_route_contains_1[_])
    not contains(lower(resource.properties.filter), "resource.type!=")
    not contains(lower(resource.properties.filter), "resource.type !=")
    contains(lower(resource.properties.filter), "gce_route")
    contains(lower(resource.properties.filter), logging_vpc_route_contains_2[_])
    not contains(lower(resource.properties.filter), "jsonPayload.event_subtype!=")
    not contains(lower(resource.properties.filter), "jsonPayload.event_subtype !=")
    contains(lower(resource.properties.filter), "compute.routes.delete")
    contains(lower(resource.properties.filter), "compute.routes.insert")
}

logging_vpc_route {
    lower(input.resources[i].type) == "google_logging_metric"
    not gc_issue["logging_vpc_route"]
}

logging_vpc_route = false {
    gc_issue["logging_vpc_route"]
}

logging_vpc_route_err = "Ensure GCP Log metric filter and alert exists for VPC network route changes" {
    gc_issue["logging_vpc_route"]
}

logging_vpc_route_metadata := {
    "Policy Code": "PR-GCP-TRF-LOG-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for VPC network route changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for VPC network route changes. Monitoring network routes deletion and insertion activities will help in identifying VPC traffic flows through an expected path. It is recommended to create a metric filter and alarm to detect activities related to the deletion and insertion of VPC network routes.",
    "Resource Type": "google_logging_metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}
