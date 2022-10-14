



# Title: MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-012

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_409']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-012|
|eval|data.rule.maria_ingress_from_any_ip_disabled|
|message|data.rule.maria_ingress_from_any_ip_disabled_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/mariadb/concepts-firewall-rules' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_SQL_012.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy will identify MariaDB firewall rule that are currently allowing ingress from all Azure-internal IP addresses  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|[]|
|service|['Databases']|



[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMariaDB.rego
