package rule

#
# PR-GCP-TRF-PRIF-001
#

default os_login_disable = null

gc_attribute_absence["os_login_disable"]{
    resource := input.resources[_]
    lower(resource.type) == "google_compute_project_metadata_item"
    not resource.key
}

gc_attribute_absence["os_login_disable"]{
    resource := input.resources[_]
    lower(resource.type) == "google_compute_project_metadata_item"
    not resource.value
}

gc_issue["os_login_disable"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_project_metadata_item"
    not contains(lower(resource.key), "enable-oslogin")
}

gc_issue["os_login_disable"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_project_metadata_item"
    contains(lower(resource.key), "enable-oslogin")
    contains(lower(resource.value), "false")
}

os_login_disable {
    lower(input.resources[_].type) == "google_compute_project_metadata_item"
    not gc_issue["os_login_disable"]
    not gc_attribute_absence["os_login_disable"]
}

os_login_disable = false {
    lower(input.resources[_].type) == "google_compute_project_metadata_item"
    gc_issue["os_login_disable"]
}

os_login_disable = false {
    lower(input.resources[_].type) == "google_compute_project_metadata_item"
    gc_attribute_absence["os_login_disable"]
}

os_login_disable_err = "Make sure that GCP Projects have OS Login disabled." {
    gc_issue["os_login_disable"]
}else ="Make sure that GCP Projects have OS Login disabled."{
    gc_attribute_absence["os_login_disable"]
}

os_login_disable_metadata := {
    "Policy Code": "PR-GCP-TRF-PRIF-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Make sure that GCP Projects have OS Login disabled.",
    "Policy Description": "This policy checks GCP Projects which have OS Login disabled. Enabling OS Login ensures that SSH keys used to connect to instances are mapped with IAM users. Revoking access to IAM user will revoke all the SSH keys associated with that particular user. It facilitates centralized and automated SSH key pair management which is useful in handling cases like a response to compromised SSH key pairs.",
    "Resource Type": "google_compute_project_metadata_item",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/projects"
}