



# Master Test ID: PR-AWS-CLD-EKS-007


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EKS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EKS-007|
|eval|data.rule.eks_with_security_group_attached|
|message|data.rule.eks_with_security_group_attached_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EKS_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure EKS cluster is configured with control plane security group attached to it.

***<font color="white">Description:</font>*** It checks if the cluster node security groups is configured or not.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'HITRUST', 'PCI-DSS', 'MAS TRM']|
|service|['eks']|



[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/eks.rego
