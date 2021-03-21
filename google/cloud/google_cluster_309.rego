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