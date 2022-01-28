package rule

#
# PR-GCP-GDF-BQ-001
#

default storage_encrypt = null

vulnerable_iam_members = ["allUsers", "allAuthenticatedUsers"]
vulnerable_roles = ["roles/editor", "roles/owner"]

gc_issue["storage_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "bigquery.v2.dataset"
    access := resource.properties.access[_]
    lower(access.role) == vulnerable_roles[_]
    lower(access.iamMember) == vulnerable_iam_members[_]
}

storage_encrypt {
    lower(input.resources[i].type) == "storage.v1.bucket"
    not gc_issue["storage_encrypt"]
}

storage_encrypt = false {
    gc_issue["storage_encrypt"]
}

storage_encrypt_err = "Ensure Big Query Datasets are not publically accessible" {
    gc_issue["storage_encrypt"]
}

storage_encrypt_metadata := {
    "Policy Code": "PR-GCP-GDF-BQ-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure Big Query Datasets are not publically accessible",
    "Policy Description": "Ensure there are no anonymously and/or publicly accessible BigQuery datasets available within your Google Cloud Platform (GCP) account. Google Cloud BigQuery datasets have Identity and Access Management (IAM) policies configured to determine who can have access to these resources",
    "Resource Type": "storage.v1.bucket",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
}
