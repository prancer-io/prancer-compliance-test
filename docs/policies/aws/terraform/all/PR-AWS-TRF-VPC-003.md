



# Title: Ensure VPC endpoint service is configured for manual acceptance


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-VPC-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-VPC-003|
|eval|data.rule.vpc_endpoint_manual_acceptance|
|message|data.rule.vpc_endpoint_manual_acceptance_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint_service' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_VPC_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** acceptance_required Indicates whether requests from service consumers to create an endpoint to your service must be accepted, we recommend you to enable this feature  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_vpc_endpoint_service']


[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego
