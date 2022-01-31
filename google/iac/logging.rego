package rule

#
# PR-GCP-GDF-LOG-001
#

default logging_audit_config = null

logging_audit_config_contains = ["protopayload.methodname=", "protopayload.methodname ="]

gc_issue["logging_audit_config"] {
    resource := input.resources[i]
    lower(resource.type) == "logging.v2.metric"
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
    lower(input.resources[i].type) == "logging.v2.metric"
    not gc_issue["logging_audit_config"]
}

logging_audit_config = false {
    gc_issue["logging_audit_config"]
}

logging_audit_config_err = "Ensure GCP Log metric filter and alert exists for Audit Configuration Changes" {
    gc_issue["logging_audit_config"]
}

logging_audit_config_metadata := {
    "Policy Code": "PR-GCP-GDF-LOG-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for Audit Configuration Changes",
    "Policy Description": "This policy identifies the GCP accounts which do not have a log metric filter and alert for Audit Configuration Changes. Configuring metric filter and alerts for Audit Configuration Changes ensures recommended state of audit configuration and hence, all the activities in project are audit-able at any point in time.",
    "Resource Type": "logging.v2.metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-GDF-LOG-002
#

default logging_iam_permission_change = null

logging_iam_permission_change_contains_1 = ["resource.type=", "resource.type ="]
logging_iam_permission_change_contains_2 = ["protopayload.methodname=", "protopayload.methodname ="]

gc_issue["logging_iam_permission_change"] {
    resource := input.resources[i]
    lower(resource.type) == "logging.v2.metric"
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
    lower(input.resources[i].type) == "logging.v2.metric"
    not gc_issue["logging_iam_permission_change"]
}

logging_iam_permission_change = false {
    gc_issue["logging_iam_permission_change"]
}

logging_iam_permission_change_err = "Ensure GCP Log metric filter and alert exists for Cloud Storage IAM permission changes" {
    gc_issue["logging_iam_permission_change"]
}

logging_iam_permission_change_metadata := {
    "Policy Code": "PR-GCP-GDF-LOG-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for Cloud Storage IAM permission changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for Cloud Storage IAM permission changes. Monitoring Cloud Storage IAM permission activities will help in reducing time to detect and correct permissions on sensitive Cloud Storage bucket and objects inside the bucket. It is recommended to create a metric filter and alarm to detect activities related to the Cloud Storage IAM permission.",
    "Resource Type": "logging.v2.metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-GDF-LOG-003
#

default logging_iam_custom_permission_change = null

logging_iam_custom_permission_change_contains_1 = ["resource.type=", "resource.type ="]
logging_iam_custom_permission_change_contains_2 = ["protopayload.methodname=", "protopayload.methodname ="]

gc_issue["logging_iam_custom_permission_change"] {
    resource := input.resources[i]
    lower(resource.type) == "logging.v2.metric"
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
    lower(input.resources[i].type) == "logging.v2.metric"
    not gc_issue["logging_iam_custom_permission_change"]
}

logging_iam_custom_permission_change = false {
    gc_issue["logging_iam_custom_permission_change"]
}

logging_iam_custom_permission_change_err = "Ensure GCP Log metric filter and alert exists for Cloud Storage IAM permission changes" {
    gc_issue["logging_iam_custom_permission_change"]
}

logging_iam_custom_permission_change_metadata := {
    "Policy Code": "PR-GCP-GDF-LOG-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Log metric filter and alert does exists for IAM custom role changes",
    "Policy Description": "This policy identifies the GCP account which does not have a log metric filter and alert for IAM custom role changes. Monitoring role creation, deletion and updating activities will help in identifying over-privileged roles at early stages. It is recommended to create a metric filter and alarm to detect activities related to the creation, deletion and updating of custom IAM Roles.",
    "Resource Type": "logging.v2.metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}


#
# PR-GCP-GDF-LOG-004
#

default logging_project_ownership = null

logging_project_ownership_contains_1 = ["protopayload.servicename=", "protopayload.servicename ="]
logging_project_ownership_contains_2 = ["protopayload.servicedata.policydelta.bindingdeltas.action=", "protopayload.servicedata.policydelta.bindingdeltas.action ="]
logging_project_ownership_contains_3 = ["protopayload.servicedata.policydelta.bindingdeltas.role=", "protopayload.servicedata.policydelta.bindingdeltas.role ="]

gc_issue["logging_project_ownership"] {
    resource := input.resources[i]
    lower(resource.type) == "logging.v2.metric"
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
    lower(input.resources[i].type) == "logging.v2.metric"
    not gc_issue["logging_project_ownership"]
}

logging_project_ownership = false {
    gc_issue["logging_project_ownership"]
}

logging_project_ownership_err = "Ensure GCP Log metric filter and alert exists for Audit Configuration Changes" {
    gc_issue["logging_project_ownership"]
}

logging_project_ownership_metadata := {
    "Policy Code": "PR-GCP-GDF-LOG-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Log metric filter and alert exists for Audit Configuration Changes",
    "Policy Description": "This policy identifies the GCP accounts which do not have a log metric filter and alert for Audit Configuration Changes. Configuring metric filter and alerts for Audit Configuration Changes ensures recommended state of audit configuration and hence, all the activities in project are audit-able at any point in time.",
    "Resource Type": "logging.v2.metric",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.metrics"
}