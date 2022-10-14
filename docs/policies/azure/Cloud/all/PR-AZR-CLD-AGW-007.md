



# Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AGW-007

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_221']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([applicationgateways.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AGW-007|
|eval|data.rule.application_gateways_v2_waf_ruleset_OWASP_active|
|message|data.rule.application_gateways_v2_waf_ruleset_OWASP_active_err|
|remediationDescription|In Azure Portal:<br>1. Navigate to the Application gateways<br>2. For each Application gateway:<br>3. Select Web application firewall from the menu<br>4. Make sure that Firewall Status is enabled and that tier is WAF.<br>Note: Choosing the WAF tier allows you to enable a web application firewall for enhanced security on your web applications. Changing from the WAF tier to the standard tier is not supported.|
|remediationFunction|PR_AZR_CLD_AGW_007.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Networking']|



[applicationgateways.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/applicationgateways.rego
