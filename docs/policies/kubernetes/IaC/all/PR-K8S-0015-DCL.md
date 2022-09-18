



# Title: Do not admit root containers


***<font color="white">Master Test Id:</font>*** TEST_POD_1

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([pod.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0015-DCL|
|eval|data.rule.run_pod_as_root|
|message|data.rule.run_pod_as_root_err|
|remediationDescription|Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.runAsUser.rule is set to either MustRunAsNonRoot or MustRunAs with the range of UIDs not including 0.|
|remediationFunction|PR-K8S-0015-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Do not generally permit containers to be run as the root user.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['daemonset', 'statefulset', 'deployment']


[pod.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/pod.rego
