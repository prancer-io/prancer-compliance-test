package rule

# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters

#
# Id: 300
#

default k8s_svc_account = null

gc_attribute_absence["k8s_svc_account"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not resource.properties.node_config
}

gc_issue["k8s_svc_account"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not resource.properties.node_config.service_account
}

gc_issue["k8s_svc_account"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    is_null(resource.properties.node_config.service_account)
}

k8s_svc_account {
    lower(input.json.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_svc_account"]
    not gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account_err = "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access" {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account_miss_err = "Kubernetes Engine Cluster attribute nodePools config missing in the resource" {
    gc_attribute_absence["k8s_svc_account"]
}

#
# Id: 301
#

default k8s_basicauth = null

gc_issue["k8s_basicauth"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.master_auth.username) > 0
}

gc_issue["k8s_basicauth"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.master_auth.password) > 0
}

k8s_basicauth {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_basicauth"]
}

k8s_basicauth = false {
    gc_issue["k8s_basicauth"]
}

k8s_basicauth_err = "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled" {
    gc_issue["k8s_basicauth"]
}

#
# Id: 302
#

default k8s_client_cert = null

gc_issue["k8s_client_cert"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.master_auth.client_certificate_config
}

gc_issue["k8s_client_cert"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.master_auth.client_certificate_config
}

k8s_client_cert {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_client_cert"]
}

k8s_client_cert = false {
    gc_issue["k8s_client_cert"]
}

k8s_client_cert_err = "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled" {
    gc_issue["k8s_client_cert"]
}

#
# Id: 303
#

default k8s_alias_ip = null

gc_issue["k8s_alias_ip"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.ip_allocation_policy
}

k8s_alias_ip {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_alias_ip"]
}

k8s_alias_ip = false {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_err = "GCP Kubernetes Engine Clusters have Alias IP disabled" {
    gc_issue["k8s_alias_ip"]
}

#
# Id: 304
#

default k8s_alpha = null

gc_issue["k8s_alpha"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    resource.properties.enable_kubernetes_alpha
}

k8s_alpha {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_alpha"]
}

k8s_alpha = false {
    gc_issue["k8s_alpha"]
}

k8s_alpha_err = "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled" {
    gc_issue["k8s_alpha"]
}

#
# Id: 305
#

default k8s_http_lbs = null

gc_issue["k8s_http_lbs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    resource.properties.addons_config.http_load_balancing.disabled
}

k8s_http_lbs {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_http_lbs"]
}

k8s_http_lbs = false {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_err = "GCP Kubernetes Engine Clusters have HTTP load balancing disabled" {
    gc_issue["k8s_http_lbs"]
}

#
# Id: 306
#

default k8s_legacy_abac = null

gc_issue["k8s_legacy_abac"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    resource.properties.enable_legacy_abac
}

k8s_legacy_abac {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac = false {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_err = "GCP Kubernetes Engine Clusters have Legacy Authorization enabled" {
    gc_issue["k8s_legacy_abac"]
}

#
# Id: 307
#

default k8s_master_auth_net = null

gc_issue["k8s_master_auth_net"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.master_authorized_networks_config
}

k8s_master_auth_net {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net = false {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_err = "GCP Kubernetes Engine Clusters have Master authorized networks disabled" {
    gc_issue["k8s_master_auth_net"]
}

#
# Id: 308
#

default k8s_net_policy = null

gc_issue["k8s_net_policy"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.network_policy.enabled
}

k8s_net_policy {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_net_policy"]
}

k8s_net_policy = false {
    gc_issue["k8s_net_policy"]
}

k8s_net_policy_err = "GCP Kubernetes Engine Clusters have Network policy disabled" {
    gc_issue["k8s_net_policy"]
}

#
# Id: 309
#

default k8s_logging = null

gc_attribute_absence["k8s_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.logging_service
}

gc_issue["k8s_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    lower(resource.properties.logging_service) == "none"
}

k8s_logging {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_logging"]
    not gc_attribute_absence["k8s_logging"]
}

k8s_logging = false {
    gc_issue["k8s_logging"]
}

k8s_logging = false {
    gc_attribute_absence["k8s_logging"]
}

k8s_logging_err = "GCP Kubernetes Engine Clusters have Stackdriver Logging disabled" {
    gc_issue["k8s_logging"]
}

k8s_logging_miss_err = "Kubernetes Engine Cluster attribute logging_service config missing in the resource" {
    gc_attribute_absence["k8s_logging"]
}

#
# Id: 310
#

default k8s_monitor = null

gc_attribute_absence["k8s_monitor"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.monitoring_service
}

gc_issue["k8s_monitor"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    lower(resource.properties.monitoring_service) == "none"
}

k8s_monitor {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_monitor"]
    not gc_attribute_absence["k8s_monitor"]
}

k8s_monitor = false {
    gc_issue["k8s_monitor"]
}

k8s_monitor = false {
    gc_attribute_absence["k8s_monitor"]
}

k8s_monitor_err = "GCP Kubernetes Engine Clusters have Stackdriver Monitoring disabled" {
    gc_issue["k8s_monitor"]
}

k8s_monitor_miss_err = "Kubernetes Engine Cluster attribute monitoring_service config missing in the resource" {
    gc_attribute_absence["k8s_monitor"]
}

#
# Id: 311
#

default k8s_binary_auth = null

gc_issue["k8s_binary_auth"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.enable_binary_authorization
}

k8s_binary_auth {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_binary_auth"]
}

k8s_binary_auth = false {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_err = "GCP Kubernetes Engine Clusters have binary authorization disabled" {
    gc_issue["k8s_binary_auth"]
}

#
# Id: 312
#

default k8s_legacy_endpoint = null

gc_issue["k8s_legacy_endpoint"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    resource.properties.node_config.metadata["disable-legacy-endpoints"] == "false"
}

gc_issue["k8s_legacy_endpoint"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    resource.properties.node_config.metadata["disable-legacy-endpoints"] == false
}

k8s_legacy_endpoint {
    lower(input.json.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint = false {
    gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_err = "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled" {
    gc_issue["k8s_legacy_endpoint"]
}

#
# Id: 313
#

default k8s_pod_security = null

gc_issue["k8s_pod_security"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.pod_security_policy_config.enabled
}

k8s_pod_security {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_pod_security"]
}

k8s_pod_security = false {
    gc_issue["k8s_pod_security"]
}

k8s_pod_security_err = "GCP Kubernetes Engine Clusters have pod security policy disabled" {
    gc_issue["k8s_pod_security"]
}

#
# Id: 315
#

default k8s_egress_metering = null

gc_issue["k8s_egress_metering"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.resource_usage_export_config.enable_network_egress_metering
}

k8s_egress_metering {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_egress_metering"]
}

k8s_egress_metering = false {
    gc_issue["k8s_egress_metering"]
}

k8s_egress_metering_err = "GCP Kubernetes Engine Clusters not configured with network traffic egress metering" {
    gc_issue["k8s_egress_metering"]
}

#
# Id: 316
#

default k8s_private = null

gc_issue["k8s_private"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.private_cluster_config
}

k8s_private {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_private"]
}

k8s_private = false {
    gc_issue["k8s_private"]
}

k8s_private_err = "GCP Kubernetes Engine Clusters not configured with private cluster" {
    gc_issue["k8s_private"]
}

#
# Id: 317
#

default k8s_private_node = null

gc_issue["k8s_private_node"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.private_cluster_config.enable_private_nodes
}

k8s_private_node {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_private_node"]
}

k8s_private_node = false {
    gc_issue["k8s_private_node"]
}

k8s_private_node_err = "GCP Kubernetes Engine Clusters not configured with private nodes feature" {
    gc_issue["k8s_private_node"]
}

#
# Id: 318
#

default k8s_node_image = null

gc_attribute_absence["k8s_node_image"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not resource.properties.node_config.image_type
}

gc_issue["k8s_node_image"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not startswith(lower(resource.properties.node_config.image_type), "cos")
}

gc_issue["k8s_node_image"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    not startswith(lower(resource.properties.nodePools[_].config.image_type), "cos")
}

k8s_node_image {
    lower(input.json.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_node_image"]
    not gc_attribute_absence["k8s_node_image"]
}

k8s_node_image = false {
    gc_issue["k8s_node_image"]
}

k8s_node_image = false {
    gc_attribute_absence["k8s_node_image"]
}

k8s_node_image_err = "GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image" {
    gc_issue["k8s_node_image"]
}

k8s_node_image_miss_err = "Kubernetes Engine Cluster attribute image_type config missing in the resource" {
    gc_attribute_absence["k8s_node_image"]
}

#
# Id: 319
#

default k8s_network = null

gc_issue["k8s_network"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.network
}

gc_issue["k8s_network"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    is_string(resource.properties.network)
    lower(resource.properties.network) == "default"
}

gc_issue["k8s_network"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    is_null(resource.properties.network)
}

k8s_network {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_network"]
}

k8s_network = false {
    gc_issue["k8s_network"]
}

k8s_network_err = "GCP Kubernetes Engine Clusters using the default network" {
    gc_issue["k8s_network"]
}

#
# Id: 321
#

default k8s_labels = null

gc_issue["k8s_labels"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.resource_labels
}

gc_issue["k8s_labels"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.resource_labels) == 0
}

k8s_labels {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_labels"]
}

k8s_labels = false {
    gc_issue["k8s_labels"]
}

k8s_labels_err = "GCP Kubernetes Engine Clusters without any label information" {
    gc_issue["k8s_labels"]
}

#
# Id: 322
#

default k8s_db_encrypt = null

gc_attribute_absence["k8s_db_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.database_encryption
}

gc_issue["k8s_db_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    lower(resource.properties.database_encryption[_].state) != "encrypted"
}

gc_issue["k8s_db_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    count(resource.properties.database_encryption[_].key_name) == 0
}

k8s_db_encrypt {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_db_encrypt"]
    not gc_attribute_absence["k8s_db_encrypt"]
}

k8s_db_encrypt = false {
    gc_issue["k8s_db_encrypt"]
}

k8s_db_encrypt = false {
    gc_attribute_absence["k8s_db_encrypt"]
}

k8s_db_encrypt_err = "GCP Kubernetes cluster Application-layer Secrets not encrypted" {
    gc_issue["k8s_db_encrypt"]
}

k8s_db_encrypt_miss_err = "Kubernetes Engine Cluster attribute database_encryption config missing in the resource" {
    gc_attribute_absence["k8s_db_encrypt"]
}

#
# Id: 323
#

default k8s_intra_node = null

gc_issue["k8s_intra_node"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    not resource.properties.enable_intranode_visibility
}

k8s_intra_node {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_intra_node"]
}

k8s_intra_node = false {
    gc_issue["k8s_intra_node"]
}

k8s_intra_node_err = "GCP Kubernetes cluster intra-node visibility disabled" {
    gc_issue["k8s_intra_node"]
}

#
# Id: 324
#

default k8s_istio = null

gc_issue["k8s_istio"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_cluster"
    resource.properties.addons_config.istio_config.disabled == false
}

k8s_istio {
    lower(input.json.resources[_].type) == "google_container_cluster"
    not gc_issue["k8s_istio"]
}

k8s_istio = false {
    gc_issue["k8s_istio"]
}

k8s_istio_err = "GCP Kubernetes cluster istio_config not enabled" {
    gc_issue["k8s_istio"]
}

#
# Id: 325
#

default k8s_zones = null

gc_issue["k8s_zones"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_container_node_pool"
    resource.properties.zone
    count(resource.properties.locations) < 3
}

k8s_zones {
    lower(input.json.resources[_].type) == "google_container_node_pool"
    not gc_issue["k8s_zones"]
}

k8s_zones = false {
    gc_issue["k8s_zones"]
}

k8s_zones_err = "GCP Kubernetes cluster Application-layer Secrets not encrypted" {
    gc_issue["k8s_zones"]
}

k8s_zones_miss_err = "GCP Kubernetes cluster not in redundant zones" {
    gc_attribute_absence["k8s_zones"]
}
