



# Title: AWS EKS unsupported Master node version.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-EKS-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-EKS-002|
|eval|data.rule.eks_version|
|message|data.rule.eks_version_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-version' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_EKS_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure your EKS Master node version is supported. This policy checks your EKS master node version and generates an alert if the version running is unsupported.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::eks::cluster']


[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/eks.rego
