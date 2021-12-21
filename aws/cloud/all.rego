package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

#
# PR-AWS-CFR-WAF-001
#

default waf_log4j_vulnerability = true

waf_log4j_vulnerability = false {
    # lower(resource.Type) == "aws::wafv2::webacl"
    Rules := input.WebACL.Rules[_]
    lower(Rules.Statement.ManagedRuleGroupStatement.Name) == "awsmanagedrulesknownbadinputsruleset"
    ExcludedRules := Rules.Statement.ManagedRuleGroupStatement.ExcludedRules[_]
    lower(ExcludedRules.Name) == "log4jrce"

}

waf_log4j_vulnerability = false {
    # lower(resource.Type) == "aws::wafv2::webacl"
    Rules := input.WebACL.Rules[_]
    not has_property(Rules.OverrideAction, "None")
}

waf_log4j_vulnerability_err = "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration" {
    not waf_log4j_vulnerability
}

waf_log4j_vulnerability_metadata := {
    "Policy Code": "PR-AWS-CFR-WAF-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration",
    "Policy Description": "Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-name"
}
