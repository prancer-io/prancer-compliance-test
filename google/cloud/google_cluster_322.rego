#
# PR-GCP-0052
#

package rule
default rulepass = false

# GCP Kubernetes cluster Application-layer Secrets not encrypted
# If GCP Kubernetes cluster Application-layer Secrets is encrypted then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(database_encryption) == 1
}

# 'databaseEncryption.state is equals to ENCRYPTED'
database_encryption["application_layer_encrypted"] {
    input.databaseEncryption.state = "ENCRYPTED"
    input.databaseEncryption.keyName != null
}

metadata := {
    "Policy Code": "PR-GCP-0052",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes cluster Application-layer Secrets not encrypted",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as Secrets, stored in etcd. Using this functionality, you can use a key, that you manage in Cloud KMS, to encrypt data at the application layer. This protects against attackers who gain access to an offline copy of etcd._x005F_x000D_ _x005F_x000D_ This policy checks your cluster for the Application-layer Secrets Encryption security feature and alerts if it is not enabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
