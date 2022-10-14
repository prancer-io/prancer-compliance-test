



# Title: Ensure that Containers are not running in privileged mode


***<font color="white">Master Test Id:</font>*** TEST_POD_2

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([pod.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0018-DCL|
|eval|data.rule.run_privileged_pod|
|message|data.rule.run_privileged_pod_err|
|remediationDescription|Use this example PodSecurityPolicy object in a file to create a policy that simply prevents the creation of privileged pods. /n apiVersion: policy/v1beta1 /n kind: PodSecurityPolicy /n metadata: /n name: example /n spec: /n privileged: false # Don't allow privileged pods! /n # The rest fills in some required fields. /n seLinux: /n rule: RunAsAny /n supplementalGroups: /n rule: RunAsAny /n runAsUser: /n  rule: RunAsAny /n fsGroup: /n rule: RunAsAny /n volumes: /n - '*' /n For more on how to enable and update pod specification using Pod Security Policy, please refer <a href='https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privileged' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0018-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Pod Security Policies are cluster-wide resources that control security sensitive aspects of pod specification. Pod Security Policy objects define a set of conditions that a pod must run with in order to be accepted into the system, as well as defaults for their related fields.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['daemonset', 'statefulset', 'deployment']


[pod.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/pod.rego
