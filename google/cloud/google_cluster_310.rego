package rule
default rulepass = false

# Kubernetes Engine Clusters have Stackdriver Monitoring disabled
# if Stackdriver Monitoring is Enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(monitoringService) == 1
}

# 'monitoringService exist and monitoringService is not equals none'
monitoringService["monitoring_service"] {
   input.monitoringService
   input.monitoringService != "none"
}
