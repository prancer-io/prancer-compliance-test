



# Master Test ID: PR-AWS-CLD-EKS-007


Master Snapshot Id: ['TEST_EKS']

type: rego

rule: [file(eks.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EKS-007|
|eval: |data.rule.eks_with_security_group_attached|
|message: |data.rule.eks_with_security_group_attached_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EKS_007.py|


severity: Medium

title: Ensure EKS cluster is configured with control plane security group attached to it.

description: It checks if the cluster node security groups is configured or not.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'HITRUST', 'PCI-DSS', 'MAS TRM']|
|service: |['eks']|



[file(eks.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/eks.rego
