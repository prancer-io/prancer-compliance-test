



# Title: Ensure GCP PostgreSQL instance database flag log_parser_stats is set to off


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-PSQL-010

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_SQLINSTANCE']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-PSQL-010|
|eval|data.rule.storage_psql_log_parser_stats|
|message|data.rule.storage_psql_log_parser_stats_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_PSQL_010.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** This policy identifies PostgreSQL database instances in which database flag log_parser_stats is not set to off. The PostgreSQL planner/optimizer is responsible to parse and verify the syntax of each query received by the server. The log_parser_stats flag enables a crude profiling method for logging parser performance statistics. Even though it can be useful for troubleshooting, it may increase the number of logs significantly and have performance overhead. It is recommended to set log_parser_stats as off.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
