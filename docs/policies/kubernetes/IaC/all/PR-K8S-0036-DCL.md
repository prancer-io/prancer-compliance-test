



# Title: Restrict Traffic Among Pods with a Network Policy


***<font color="white">Master Test Id:</font>*** TEST_NETWORK_POLICY

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([networkPolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0036-DCL|
|eval|data.rule.empty_ingress|
|message|data.rule.empty_ingress_err|
|remediationDescription|Pods in a cluster can communicate with each other and should be controlled using Network Policies as needed for your workload. Network policies are implemented by the network plugin, so you must be using a networking solution which supports NetworkPolicy - simply creating the resource without a controller to implement it will have no effect. Kubernetes' Network Policies make it much more difficult for attackers to move laterally within your cluster. You can also use the Kubernetes Network Policy API to create Pod-level firewall rules. These firewall rules determine which Pods and services can access one another inside your cluster. You can find an example of NetworkPolicy : <a href='https://kubernetes.io/docs/concepts/services-networking/network-policies/#the-networkpolicy-resource' target='_blank'>here</a> For more information on NetworkPolicy, please refer <a href='https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#networkpolicy-v1-networking-k8s-io' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0036-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Network policies are Kubernetes resources that control the traffic between pods and/or network endpoints. They uses labels to select pods and specify the traffic that is directed toward those pods using rules.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['networkpolicy']


[networkPolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/networkPolicy.rego
