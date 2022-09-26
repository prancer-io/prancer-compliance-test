



# Title:  Ensure pods outside of kube-system do not have access to node volume


***<font color="white">Master Test Id:</font>*** TEST_POD_4

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([pod.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0057-DCL|
|eval|data.rule.hostpath_mount|
|message|data.rule.hostpath_mount_err|
|remediationDescription|Please refer to the Kubernetes documentation on how to configure the hostpath <a href='https://kubernetes.io/docs/concepts/storage/volumes/#hostpath' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0057-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>***  A hostPath volume mounts a file or directory from the host node's filesystem into your Pod. This is not something that most Pods will need, but it offers a powerful escape hatch for some applications. It is important to watch out when using this type of volume because; when Kubernetes adds resource-aware scheduling, as is planned, it will not be able to account for resource used by a hostPath.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['daemonset', 'statefulset', 'deployment']


[pod.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/pod.rego
