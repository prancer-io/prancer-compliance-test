package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys

#
# PR-GCP-CLD-SAK-001
#

default svc_account_key = null


gc_attribute_absence["svc_account_key"] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    not input.name
}

source_path[{"svc_account_key": metadata}] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    not input.name
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "name"]
        ],
    }
}

gc_issue["svc_account_key"] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(input.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(input.validAfterTime) > 7776000000000000
}

source_path[{"svc_account_key": metadata}] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(input.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(input.validAfterTime) > 7776000000000000
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "validAfterTime"]
        ],
    }
}


svc_account_key {
    # lower(input.resources[i].type) == "iam.v1.serviceaccounts.key"
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
    "Policy Code": "PR-GCP-CLD-SAK-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP User managed service account keys are not rotated for 90 days",
    "Policy Description": "This policy identifies user-managed service account keys which are not rotated from last 90 days or more. Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen. It is recommended that all user-managed service account keys are regularly rotated.",
    "Resource Type": "iam.v1.serviceaccounts.key",
    "Policy Help URL": "",
    # "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys"
}


#
# PR-GCP-CLD-SAK-009
#
## "iam.v1.serviceaccounts.key" 

default svc_ac_user_has_svc_ac_key = true

svc_ac_user_has_svc_ac_key = false {
    X := input.GOOGLE_SERVICE_AC_KEY[_]
    Y := input.GOOGLE_SERVICE_AC[_]
    contains(X.name, "iam.gserviceaccount.com")
    contains(lower(X.name), lower(Y.email))
    contains(X.keyType, "USER_MANAGED")
}

svc_ac_user_has_svc_ac_key_err = "Ensure, GCP User managed service accounts have user managed service account keys." {
    not svc_ac_user_has_svc_ac_key
}

svc_ac_user_has_svc_ac_key_metadata := {
    "Policy Code": "PR-GCP-CLD-SAK-009",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP User managed service accounts have user managed service account keys.",
    "Policy Description": "This policy checks user managed service accounts that use user managed service account keys instead of Google-managed. For user-managed keys, the User has to take ownership of key management activities. Even after owner precaution, keys can be easily leaked by common development malpractices like checking keys into the source code or leaving them in downloads directory or accidentally leaving them on support blogs/channels. So It is recommended to limit the use of User-managed service account keys and instead use Google-managed keys which can not be downloaded.",
    "Resource Type": "iam.v1.serviceaccounts.key",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts",
    "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys"
}


#
# PR-GCP-CLD-SAK-010
#

default api_key_rotation_90_days = null

gc_issue["api_key_rotation_90_days"] {
    time.parse_rfc3339_ns(input.createTime) > 1659248441
}

api_key_rotation_90_days {
    not gc_issue["api_key_rotation_90_days"]
}

api_key_rotation_90_days = false {
    gc_issue["api_key_rotation_90_days"]
}

api_key_rotation_90_days_err = "Ensure, GCP API key not rotating in every 90 days." {
    gc_issue["api_key_rotation_90_days"]
}

api_key_rotation_90_days_metadata := {
    "Policy Code": "PR-GCP-CLD-SAK-010",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP API key not rotating in every 90 days.",
    "Policy Description": "This policy identifies GCP API keys for which the creation date is aged more than 90 days. Google recommends using the standard authentication flow instead of API Keys. However, there are limited cases where API keys are more appropriate. API keys should be rotated to ensure that data cannot be accessed with an old key that might have been lost, cracked, or stolen.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}

#
# PR-GCP-CLD-SAK-011
#

default api_target_not_exist = true

api_target_not_exist = false{
    not  has_property(input.restrictions, "apiTargets")
}

api_target_not_exist_err = "Ensure, GCP API key not restricting any specific API." {
    not api_target_not_exist
}

api_target_not_exist_metadata := {
    "Policy Code": "PR-GCP-CLD-SAK-011",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP API key not restricting any specific API.",
    "Policy Description": "This policy checks GCP API keys that are not restricting any specific APIs. API keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API keys to use (call) only APIs required by an application.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}


#
# PR-GCP-CLD-SAK-012
#

default api_key_has_no_specific_restriction = null

gc_attribute_absence["api_key_has_no_specific_restriction"] {   
    not has_property(input.restrictions, "browserKeyRestrictions")
    not has_property(input.restrictions, "serverKeyRestrictions")
    not has_property(input.restrictions, "androidKeyRestrictions")
    not has_property(input.restrictions, "iosKeyRestrictions")
}

gc_issue["api_key_has_no_specific_restriction"]{
    has_property(input.restrictions, "browserKeyRestrictions")
    browser_key_restriction := input.restrictions.browserKeyRestrictions[_]
    contains(browser_key_restriction.allowedReferrers[_], "*")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    has_property(input.restrictions, "browserKeyRestrictions")
    browser_key_restriction := input.restrictions.browserKeyRestrictions[_]
    contains(lower(browser_key_restriction.allowedReferrers[_]), "*.[tld]")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    has_property(input.restrictions, "browserKeyRestrictions")
    browser_key_restriction := input.restrictions.browserKeyRestrictions[_]
    contains(lower(browser_key_restriction.allowedReferrers[_]), "*.[tld]/*")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    contains(server_key_restriction.allowedIps[_], "0.0.0.0")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    contains(server_key_restriction.allowedIps[_], "0.0.0.0/0")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    contains(server_key_restriction.allowedIps[_], "::/0")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    contains(server_key_restriction.allowedIps[_], "::0")
}   

api_key_has_no_specific_restriction {
    not gc_issue["api_key_has_no_specific_restriction"]
    not gc_attribute_absence["api_key_has_no_specific_restriction"]
}

api_key_has_no_specific_restriction = false {
    gc_issue["api_key_has_no_specific_restriction"]
    gc_attribute_absence["api_key_has_no_specific_restriction"]
    
}

api_key_has_no_specific_restriction_err = "Ensure, GCP API key not restricted to use by specified Hosts and Apps." {
    gc_issue["api_key_has_no_specific_restriction"]
    gc_attribute_absence["api_key_has_no_specific_restriction"]
}

api_key_has_no_specific_restriction_metadata := {
    "Policy Code": "PR-GCP-CLD-SAK-012",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP API key not restricted to use by specified Hosts and Apps.",
    "Policy Description": "This policy checks GCP API key not restricted to use by specified Hosts and Apps. Unrestricted keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API key usage to trusted hosts, HTTP referrers and apps.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}