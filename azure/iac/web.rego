package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites

# PR-AZR-0139-ARM

default https_only = null

azure_attribute_absence ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.httpsOnly
}

azure_issue ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.httpsOnly != true
}

https_only {
    azure_attribute_absence["https_only"]
}

https_only {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_issue["https_only"]
}

https_only = false {
    azure_issue["https_only"]
}

https_only_err = "microsoft.web/sites resource property httpsOnly missing in the resource" {
    azure_attribute_absence["https_only"]
} else = "Azure App Service Web app does not redirect HTTP to HTTPS" {
    azure_issue["https_only"]
}

https_only_metadata := {
    "Policy Code": "PR-AZR-0139-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure App Service Web app redirects HTTP to HTTPS",
    "Policy Description": "Azure Web Apps by default allows sites to run under both HTTP and HTTPS, and can be accessed by anyone using non-secure HTTP links. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. We recommend you enforce HTTPS-only traffic to increase security. This will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}