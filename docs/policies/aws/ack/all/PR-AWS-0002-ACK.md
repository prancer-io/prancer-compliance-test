



# Title: AWS API Gateway endpoints without client certificate authentication


***<font color="white">Master Test Id:</font>*** TEST_API_GATEWAY

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([apigateway.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0002-ACK|
|eval|data.rule.api_gw_cert|
|message|data.rule.api_gw_cert_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible.<br><br>Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[apigateway.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/apigateway.rego
