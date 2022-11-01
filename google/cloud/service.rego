package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


# PR-GCP-CLD-SVC-001
#

default vulnerability_scan_disabled = true

vulnerability_scan_disabled = false {
    input
    contains(input.name, "containerscanning.googleapis.com")
    upper(input.state) == "ENABLED"
}

vulnerability_scan_disabled_err = "Ensure, GCP GCR Container Vulnerability Scanning is disabled." {
    not vulnerability_scan_disabled   
}

vulnerability_scan_disabled_metadata := {
    "Policy Code": "PR-GCP-CLD-SVC-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Ensure, GCP GCR Container Vulnerability Scanning is disabled.",
    "Policy Description": "This policy identifies GCP accounts where GCR Container Vulnerability Scanning is not enabled. GCR Container Analysis and other third party products allow images stored in GCR to be scanned for known vulnerabilities. Vulnerabilities in software packages can be exploited by hackers or malicious users to obtain unauthorized access to local cloud resources. It is recommended to enable vulnerability scanning for images stored in Google Container Registry.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
}