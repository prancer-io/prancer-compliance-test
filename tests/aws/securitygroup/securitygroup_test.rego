package rule_test

import data.rule

# Test: Security group with no open SSH port should pass
test_port_22_compliant {
    input := {
        "SecurityGroups": [{
            "GroupId": "sg-12345",
            "IpPermissions": [{
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
            }]
        }]
    }
    # Private CIDR should not trigger the rule
    not rule.port_22 == false with input as input
}

# Test: Security group with SSH open to 0.0.0.0/0 should fail
test_port_22_non_compliant {
    input := {
        "SecurityGroups": [{
            "GroupId": "sg-12345",
            "IpPermissions": [{
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        }]
    }
    rule.port_22 == false with input as input
}

# Test: Empty security groups should return null (not false positive)
test_port_22_empty_input {
    input := {}
    rule.port_22 == null with input as input
}

# Test: Security group with no security groups array should return null
test_port_22_no_security_groups {
    input := {
        "OtherResource": {}
    }
    rule.port_22 == null with input as input
}

# Test: RDP port (3389) open to internet should fail
test_port_3389_non_compliant {
    input := {
        "SecurityGroups": [{
            "GroupId": "sg-12345",
            "IpPermissions": [{
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        }]
    }
    rule.port_3389 == false with input as input
}

# Test: MySQL port (3306) open to internet should fail
test_port_3306_non_compliant {
    input := {
        "SecurityGroups": [{
            "GroupId": "sg-12345",
            "IpPermissions": [{
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        }]
    }
    rule.port_3306 == false with input as input
}

# Test: IPv6 unrestricted access should also fail
test_port_22_ipv6_non_compliant {
    input := {
        "SecurityGroups": [{
            "GroupId": "sg-12345",
            "IpPermissions": [{
                "FromPort": 22,
                "ToPort": 22,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
            }]
        }]
    }
    rule.port_22 == false with input as input
}
