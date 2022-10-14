



# Title: AWS EKS unsupported Master node version.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EKS-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EKS-002|
|eval|data.rule.eks_version|
|message|data.rule.eks_version_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EKS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure your EKS Master node version is supported. This policy checks your EKS master node version and generates an alert if the version running is unsupported.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_eks_cluster']


[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/eks.rego
