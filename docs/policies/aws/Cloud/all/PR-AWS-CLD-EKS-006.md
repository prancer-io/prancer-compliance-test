



# Title: Ensure AWS EKS only uses latest versions of Kubernetes.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EKS-006

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EKS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EKS-006|
|eval|data.rule.eks_approved_kubernetes_version|
|message|data.rule.eks_approved_kubernetes_version_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EKS_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if an approved version of Kubernetes is used for EKS cluster or not.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'HITRUST', 'PCI-DSS', 'MAS TRM']|
|service|['eks']|



[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/eks.rego
