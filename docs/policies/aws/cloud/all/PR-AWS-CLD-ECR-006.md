



# Master Test ID: PR-AWS-CLD-ECR-006


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ECR']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ECR-006|
|eval|data.rule.ecr_accessible_only_via_private_endpoint|
|message|data.rule.ecr_accessible_only_via_private_endpoint_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html#ECR.Client.get_repository_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ECR_006.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure ECR resources are accessible only via private endpoint.

***<font color="white">Description:</font>*** It checks if the container registry is accessible over the internet, GS mandates to keep the container repository private from GS network only  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI DSS', 'GDPR']|
|service|['ecr']|



[ecr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
