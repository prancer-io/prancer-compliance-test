#
# PR-GCP-0039
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Stackdriver Logging disabled
# If stackdriver logging is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(loggingService) == 1
}

# 'loggingService have some value and loggingService not equals none'
loggingService["LoggingService"] {
    input.loggingService
    input.loggingService != "none"
}

metadata := {
    "Policy Code": "PR-GCP-0039",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Stackdriver Logging disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Stackdriver Logging. Enabling Stackdriver Logging will let the Kubernetes Engine to collect, process, and store your container and system logs in a dedicated persistent data store.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
