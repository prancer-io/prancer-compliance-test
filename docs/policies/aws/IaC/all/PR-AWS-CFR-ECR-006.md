



# Title: Ensure ECR resources are accessible only via private endpoint.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ECR-006

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ECR-006|
|eval|data.rule.ecr_accessible_only_via_private_endpoint|
|message|data.rule.ecr_accessible_only_via_private_endpoint_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ECR_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the container registry is accessible over the internet, GS mandates to keep the container repository private from GS network only  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI DSS', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ecr::repository']


[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecr.rego
