package rule


has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys

#
# PR-GCP-GDF-SAK-001
#

default svc_account_key = null


gc_attribute_absence["svc_account_key"] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    not resource.properties.name
}

source_path[{"svc_account_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    not resource.properties.name
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "name"]
        ],
    }
}

gc_issue["svc_account_key"] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(resource.properties.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(resource.properties.validAfterTime) > 7776000000000000
}

source_path[{"svc_account_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(resource.properties.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(resource.properties.validAfterTime) > 7776000000000000
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "validAfterTime"]
        ],
    }
}


svc_account_key {
    lower(input.resources[i].type) == "iam.v1.serviceaccounts.key"
    not gc_issue["svc_account_key"]
    not gc_attribute_absence["svc_account_key"]
}

svc_account_key = false {
    gc_issue["svc_account_key"]
}

svc_account_key = false {
    gc_attribute_absence["svc_account_key"]
}

svc_account_key_err = "GCP User managed service account keys are not rotated for 90 days" {
    gc_issue["svc_account_key"]
}

svc_account_key_miss_err = "GCP User managed service account keys attribute name missing in the resource" {
    gc_attribute_absence["svc_account_key"]
}

svc_account_key_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP User managed service account keys are not rotated for 90 days",
    "Policy Description": "This policy identifies user-managed service account keys which are not rotated from last 90 days or more. Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen. It is recommended that all user-managed service account keys are regularly rotated.",
    "Resource Type": "iam.v1.serviceaccounts.key",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys"
}


#
# PR-GCP-GDF-SAK-002
#
# "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"

default non_gcp_account_access_denied = null

gc_issue["non_gcp_account_access_denied"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not contains(lower(resource.properties.policy.bindings[_].members[_]), "gserviceaccount.com")
}

non_gcp_account_access_denied {
    lower(input.resources[i].type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied = false {
    gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied_err = "Ensure, Non-corporate accounts have access to Google Cloud Platform (GCP) resources." {
    gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, Non-corporate accounts have access to Google Cloud Platform (GCP) resources.",
    "Policy Description": "Ensure, using personal accounts to access GCP resources may compromise the security of your business. Using fully managed corporate Google accounts to access Google Cloud Platform resources is recommended to make sure that your resources are secure. NOTE : This policy requires customization before using it. To customize, follow the steps mentioned: (1) Clone this policy and replace '@yourcompanydomainname' in RQL with your domain name. For example: 'user does not end with @prismacloud.io and user does not end with gserviceaccount.com'. (2) For multiple domains, update the RQL with conditions for each domain. For example: 'user does not end with @prismacloud.io and user does not end with @prismacloud.com and user does not end with gserviceaccount.com'.",
    "Resource Type": "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-GDF-SAK-003
#
# "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"

default admin_privileges_enabled = null

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.properties.policy.bindings[_].members[_]), "iam.gserviceaccount.com")
    contains(lower(resource.properties.policy.bindings[_].role), "admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.properties.policy.bindings[_].members[_]), "iam.gserviceaccount.com")
    contains(lower(resource.properties.policy.bindings[_].role), "roles/editor")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.properties.policy.bindings[_].members[_]), "iam.gserviceaccount.com")
    contains(lower(resource.properties.policy.bindings[_].role), "roles/owner")
}

admin_privileges_enabled {
    lower(input.resources[i].type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled = false {
    gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled_err = "Ensure, GCP IAM Service account has admin privileges." {
    gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP IAM Service account has admin privileges.",
    "Policy Description": "Ensure, service accounts which have admin privileges. Application uses the service account to make requests to the Google API of a service so that the users aren't directly involved. It is recommended not to use admin access for ServiceAccount.",
    "Resource Type": "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-GDF-SAK-004
#
# "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"

default overly_permissive_ac_privileges = null

gc_issue["overly_permissive_ac_privileges"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.bindings[_].role), "roles/iam.serviceaccountadmin")
    contains(lower(resource.bindings[_].role), "roles/iam.serviceaccountuser")
}

overly_permissive_ac_privileges {
    lower(input.resources[i].type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not gc_issue["overly_permissive_ac_privileges"]
}

overly_permissive_ac_privileges = false {
    gc_issue["overly_permissive_ac_privileges"]
}

overly_permissive_ac_privileges_err = "Ensure, GCP IAM Users have overly permissive service account privileges." {
    gc_issue["overly_permissive_ac_privileges"]
}

overly_permissive_ac_privileges_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP IAM Users have overly permissive service account privileges.",
    "Policy Description": "Ensure, IAM users which have overly permissive service account privileges. Any user should not have Service Account Admin and Service Account User, both roles assigned at a time. Built-in/Predefined IAM role Service Account admin allows the user to create, delete, manage service accounts. Built-in/Predefined IAM role Service Account User allows the user to assign service accounts to Apps/Compute Instances. It is recommended to follow the principle of 'Separation of Duties' ensuring that one individual does not have all the necessary permissions to be able to complete a malicious action or meant to help avoid security or privacy incidents and errors.",
    "Resource Type": "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-GDF-SAK-005
#
# "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"

default overly_permissive_kms_privileges = null

gc_issue["overly_permissive_kms_privileges"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.bindings[_].role), "roles/cloudkms.admin")
    contains(lower(resource.bindings[_].role), "roles/cloudkms.crypto")
}

overly_permissive_kms_privileges {
    lower(input.resources[i].type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not gc_issue["overly_permissive_kms_privileges"]
}

overly_permissive_kms_privileges = false {
    gc_issue["overly_permissive_kms_privileges"]
}

overly_permissive_kms_privileges_err = "Ensure, GCP IAM user have overly permissive Cloud KMS roles." {
    gc_issue["overly_permissive_kms_privileges"]
}

overly_permissive_kms_privileges_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP IAM user have overly permissive Cloud KMS roles.",
    "Policy Description": "Ensure, IAM users who have overly permissive Cloud KMS roles. Built-in/Predefined IAM role Cloud KMS Admin allows the user to create, delete, and manage service accounts. Built-in/Predefined IAM role Cloud KMS CryptoKey Encrypter/Decrypter allows the user to encrypt and decrypt data at rest using the encryption keys. It is recommended to follow the principle of 'Separation of Duties' ensuring that one individual does not have all the necessary permissions to be able to complete a malicious action.",
    "Resource Type": "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-GDF-SAK-006
#
# "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"

default service_ac_privileges = null

gc_issue["service_ac_privileges"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.bindings[_].role), "roles/iam.serviceaccountactor")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.bindings[_].role), "roles/iam.serviceaccountuser")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    contains(lower(resource.bindings[_].role), "roles/iam.serviceaccounttokencreator")
}

service_ac_privileges {
    lower(input.resources[i].type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not gc_issue["service_ac_privileges"]
}

service_ac_privileges = false {
    gc_issue["service_ac_privileges"]
}

service_ac_privileges_err = "Ensure, GCP IAM user with service account privileges." {
    gc_issue["service_ac_privileges"]
}

service_ac_privileges_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP IAM user with service account privileges.",
    "Policy Description": "Ensure, IAM users don't have service account privileges. Adding any user as service account actor will enable these users to have service account privileges. Adding only authorized corporate IAM users as service account actors will make sure that your information is secure.",
    "Resource Type": "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-GDF-SAK-007
#
# "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"

list_var = ["appspot.gserviceaccount.com",
            "developer.gserviceaccount.com",
            "cloudservices.gserviceaccount.com",
            "system.gserviceaccount.com",
            "cloudbuild.gserviceaccount.com"]

default iam_primitive_roles_in_use = null

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
  count([c | contains(input.resources[i].bindings[_].members[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[i].bindings[_].role), "roles/editor")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
  count([c | contains(input.resources[i].bindings[_].members[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[i].bindings[_].role), "roles/owner")
}

iam_primitive_roles_in_use {
    lower(input.resources[i].type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not gc_issue["iam_primitive_roles_in_use"]
}

iam_primitive_roles_in_use = false {
    gc_issue["iam_primitive_roles_in_use"]
}

iam_primitive_roles_in_use_err = "Ensure, GCP IAM primitive roles are in use." {
    gc_issue["iam_primitive_roles_in_use"]
}

iam_primitive_roles_in_use_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP IAM primitive roles are in use.",
    "Policy Description": "Ensure, GCP IAM users assigned with primitive roles. Primitive roles are Roles that existed prior to Cloud IAM. Primitive roles (owner, editor) are built-in and provide a broader access to resources making them prone to attacks and privilege escalation. Predefined roles provide more granular controls than primitive roles and therefore Predefined roles should be used. Note: For a new GCP project, service accounts are assigned with role/editor permissions. GCP recommends not to revoke the permissions on the SA account. Reference: https://cloud.google.com/iam/docs/service-accounts Limitation: This policy alerts for Service agents which are Google-managed service accounts. Service Agents are by default assigned with some roles by Google cloud and these roles shouldn't be revoked. Reference: https://cloud.google.com/iam/docs/service-agents In case any specific service agent needs to be bypassed, this policy can be cloned and modified accordingly.",
    "Resource Type": "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-GDF-SAK-008
#
# "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"

default audit_not_config_proper = null

gc_issue["audit_not_config_proper"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not contains(lower(resource.auditConfigs[_].service), "allservices")
}

gc_issue["audit_not_config_proper"] {
    resource := input.resources[i]
    lower(resource.type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
  has_property(resource.auditConfigs[_].auditLogConfigs[_], "exemptedMembers")
  count(resource.auditConfigs[_].auditLogConfigs[_].exemptedMembers) != 0
}

audit_not_config_proper {
    lower(input.resources[i].type) == "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy"
    not gc_issue["audit_not_config_proper"]
}

audit_not_config_proper = false {
    gc_issue["audit_not_config_proper"]
}

audit_not_config_proper_err = "Ensure, GCP Project audit logging is not configured properly across all services and all users in a project." {
    gc_issue["audit_not_config_proper"]
}

audit_not_config_proper_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP Project audit logging is not configured properly across all services and all users in a project.",
    "Policy Description": "Ensure, GCP projects in which cloud audit logging is not configured properly across all services and all users. It is recommended that cloud audit logging is configured to track all Admin activities and read, write access to user data. Logs should be captured for all users and there should be no exempted users in any of the audit config section.",
    "Resource Type": "gcp-types/iam-v1:iam.projects.serviceaccounts.getiampolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}