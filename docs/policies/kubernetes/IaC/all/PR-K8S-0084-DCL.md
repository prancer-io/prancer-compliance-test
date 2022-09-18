



# Title: Apply Security Context to Your Pods and Containers


***<font color="white">Master Test Id:</font>*** TEST_POD_5

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([pod.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0084-DCL|
|eval|data.rule.pod_selinux|
|message|data.rule.pod_selinux_err|
|remediationDescription|Follow the Kubernetes documentation and apply security contexts to your pods. For a suggested list of security contexts, you may refer to the CIS Security Benchmark for Docker Containers. Please refer <a href='https://kubernetes.io/docs/concepts/policy/security-context/' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0084-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Apply Security Context to Your Pods and Containers. A security context defines the operating system security settings (uid, gid, capabilities, SELinux role, etc..) applied to a container. When designing your containers and pods, make sure that you configure the security context for your pods, containers, and volumes. A security context is a property defined in the deployment yaml. It controls the security parameters that will be assigned to the pod/container/volume.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['daemonset', 'statefulset', 'deployment']


[pod.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/pod.rego
