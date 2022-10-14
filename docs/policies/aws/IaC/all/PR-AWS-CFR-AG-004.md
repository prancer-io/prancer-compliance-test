



# Title: Ensure that API Gateway has enabled access logging


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AG-004

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([api_gateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AG-004|
|eval|data.rule.gateway_logging_enable|
|message|data.rule.gateway_logging_enable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AG_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Enabling the custom access logging option in API Gateway allows delivery of custom logs to CloudWatch Logs, which can be analyzed using CloudWatch Logs Insights. Using custom domain names in Amazon API Gateway allows insights into requests sent to each custom domain name.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::apigateway::stage']


[api_gateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/api_gateway.rego
