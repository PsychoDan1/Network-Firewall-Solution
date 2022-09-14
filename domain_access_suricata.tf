locals {
  list = yamldecode(file("${path.module}/settings.yaml"))["rule_groups"]
  fw_group_rule = flatten([for rule in local.list : {
    "name"            = rule.name
    "allowed-domains" = rule.allowed-domains
    "definition"      = rule.source
    }
  ])
}


resource "aws_networkfirewall_rule_group" "limit-Domain-Access-v1" {
  name     = "suricata-automation-test"
  capacity = 1000
  type     = "STATEFUL"
  rule_group {
    rule_variables {
      ip_sets {
        key = "SQUID_EP"
        ip_set {
          definition = ["10.129.3.154/32","10.129.3.29/32"]
        }
      }
      dynamic "ip_sets" {
        for_each = local.fw_group_rule
        content {
          key = ip_sets.value.name
          ip_set {
            definition = [ip_sets.value.definition]
          }
        }
      }
    }
    rules_source {
      rules_string = file("suricata_rules")
 }
}
  tags = {
    Name = "suricata-automation"
  }
}

resource "aws_networkfirewall_rule_group" "block-all-domains" {
  name     = "block-all-domains"
  capacity = 100
  type     = "STATEFUL"
  rule_group {
    rule_variables {
      ip_sets {
        key = "SQUID_EP"
        ip_set {
          definition = ["10.129.3.154/32","10.129.3.29/32"]
        }
      }
      ip_sets {
        key = "LOCAL_SECURITY_ZONE"
        ip_set {
          definition = ["10.129.0.0/16"]
        }
      }
    }
    rules_source {
      rules_string = <<EOF
drop http $LOCAL_SECURITY_ZONE any -> $SQUID_EP any (http.header_names; content:"|0d 0a|"; startswith; msg:"Drop All HTTP Requests to Proxy"; priority:1; flow:to_server, established; sid:1; rev:1;)
drop tls $LOCAL_SECURITY_ZONE any -> $SQUID_EP any (msg:"not matching any TLS allowlisted FQDNs"; priority:1; flow:to_server, established; sid:2; rev:1;)
      EOF
    }
  }
  tags = {
    Name = "block-all-domains"
    }  
}



resource "aws_networkfirewall_firewall_policy" "used_policy" {
  name = "${yamldecode(file("settings.yaml"))["nwf_policy_name"]}"
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
  # BE CAREFULL DELETES ALL POLICY MANAGED GROUP RULES 
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.block-all-domains.arn
    }
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.limit-Domain-Access-v1.arn
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/AbusedLegitBotNetCommandAndControlDomainsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/AbusedLegitMalwareDomainsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/BotNetCommandAndControlDomainsActionOrder"
    }
      stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/MalwareDomainsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesExploitsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesEmergingEventsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesEmergingEventsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesBotnetWindowsActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesBotnetWebActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesBotnetActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesMalwareCoinminingActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesMalwareActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesIOCActionOrder"
    }
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:eu-central-1:aws-managed:stateful-rulegroup/ThreatSignaturesFUPActionOrder"
    }
  }
}  