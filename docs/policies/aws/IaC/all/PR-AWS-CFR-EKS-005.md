



# Title: Ensure communication to and from EKS remains private.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-EKS-005

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-EKS-005|
|eval|data.rule.eks_pblic_endpoint|
|message|data.rule.eks_pblic_endpoint_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-provider' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_EKS_005.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure communication to and from EKS remains private.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::eks::cluster']


[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/eks.rego
