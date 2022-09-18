



# Title: GCP Kubernetes cluster istioConfig not enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-CLT-024

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([container.v1.cluster.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-CLT-024|
|eval|data.rule.k8s_istio|
|message|data.rule.k8s_istio_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Istio is an open service mesh that provides a uniform way to connect, manage, and secure microservices. It supports managing traffic flows between services, enforcing access policies, and aggregating telemetry data, all without requiring changes to the microservice code.<br><br> This policy checks your cluster for the Istio add-on feature and alerts if it is not enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_container_node_pool', 'google_container_cluster']


[container.v1.cluster.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/container.v1.cluster.rego
