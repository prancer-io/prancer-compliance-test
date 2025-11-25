package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


#
# PR-GCP-CLD-APE-001
#

default app_engine_iap_disabled = null

gc_issue["app_engine_iap_disabled"] {
    upper(input.servingStatus) == "SERVING"
    has_property(input, "iap")
}

gc_issue["app_engine_iap_disabled"] {
    upper(input.servingStatus) == "SERVING"
    count([c | has_property(input.iap, "enabled"); c=1]) == 0
}

gc_issue["app_engine_iap_disabled"] {
    upper(input.servingStatus) == "SERVING"
    input.iap.enabled == "false"
}

app_engine_iap_disabled {
    not gc_issue["app_engine_iap_disabled"]
}

app_engine_iap_disabled = false {
    gc_issue["app_engine_iap_disabled"]
}

app_engine_iap_disabled_err = "Ensure, GCP App Engine Identity-Aware Proxy is disabled." {
    gc_issue["app_engine_iap_disabled"]
}

app_engine_iap_disabled_metadata := {
    "Policy Code": "PR-GCP-CLD-APE-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure, GCP App Engine Identity-Aware Proxy is disabled.",
    "Policy Description": "This policy identifies GCP App Engine applications for which Identity-Aware Proxy(IAP) is disabled.  IAP is used to enforce access control policies for applications and resources. It works with signed headers or the App Engine standard environment Users API to secure your app. It is recommended to enable Identity-Aware Proxy for securing the App engine. Reference: https://cloud.google.com/iap/docs/concepts-overview ",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": " https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps "
}