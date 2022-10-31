package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


#
# PR-GCP-TRF-APE-001
#

default app_engine_iap_disabled = true

gc_issue["app_engine_iap_disabled"]{
    
    resource := input.resources[_]
    lower(resource.type) == "google_app_engine_application"
    upper(resource.properties.serving_status) == "SERVING"
    has_property(resource.properties, "iap")
}

gc_issue["app_engine_iap_disabled"]{
    
    resource := input.resources[_]
    lower(resource.type) == "google_app_engine_application"
    upper(resource.properties.serving_status) == "SERVING"
    count([c | has_property(resource.properties.iap, "enabled"); c=1]) == 0
}

gc_issue["app_engine_iap_disabled"]{
    
    resource := input.resources[_]
    lower(resource.type) == "google_app_engine_application"
    upper(resource.properties.serving_status) == "SERVING"
    resource.properties.iap.enabled == "false"
}

app_engine_iap_disabled_err = "Ensure, GCP App Engine Identity-Aware Proxy is disabled." {
    gc_issue["app_engine_iap_disabled"]
}

app_engine_iap_disabled_metadata := {
    "Policy Code": "PR-GCP-TRF-APE-001",
    "Type": "Iac",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP App Engine Identity-Aware Proxy is disabled.",
    "Policy Description": "This policy identifies GCP App Engine applications for which Identity-Aware Proxy(IAP) is disabled.  IAP is used to enforce access control policies for applications and resources. It works with signed headers or the App Engine standard environment Users API to secure your app. It is recommended to enable Identity-Aware Proxy for securing the App engine. Reference: https://cloud.google.com/iap/docs/concepts-overview ",
    "Resource Type": "google_app_engine_application",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps"
}