



# Title: The default namespace should not be used


***<font color="white">Master Test Id:</font>*** TEST_POD_3

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([pod.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0030-DCL|
|eval|data.rule.pod_default_ns|
|message|data.rule.pod_default_ns_err|
|remediationDescription|Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace.|
|remediationFunction|PR-K8S-0030-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Kubernetes provides a default namespace, where objects are placed if no namespace is specified for them. Placing objects in this namespace makes application of RBAC and other controls more difficult.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['daemonset', 'statefulset', 'deployment']


[pod.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/pod.rego
