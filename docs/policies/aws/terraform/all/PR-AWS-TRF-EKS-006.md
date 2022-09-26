



# Title: Ensure AWS EKS only uses latest versions of Kubernetes.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EKS-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EKS-006|
|eval|data.rule.eks_approved_kubernetes_version|
|message|data.rule.eks_approved_kubernetes_version_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EKS_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if an approved version of Kubernetes is used for EKS cluster or not.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'HITRUST', 'PCI-DSS', 'MAS TRM']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_eks_cluster']


[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/eks.rego
