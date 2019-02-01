[![Build Status](https://travis-ci.org/stevespringett/owasp-risk-rating-calculator.svg?branch=master)](https://travis-ci.org/stevespringett/owasp-risk-rating-calculator)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/cb8fdf4b23df4ac993cadbbeb14c743c)](https://www.codacy.com/app/stevespringett/owasp-risk-rating-calculator?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stevespringett/owasp-risk-rating-calculator&amp;utm_campaign=Badge_Grade)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)][Apache 2.0]

OWASP Risk Rating Calculator
=====================================

OWASP Risk Rating Calculator is a Java library for calculating OWASP Risk Rating scores.

Compiling
-------------------

> $ mvn clean package

Usage Example
-------------------
```java
OwaspRiskRating riskRating = new OwaspRiskRating()
    .withSkillLevel(ThreatAgentFactor.SkillLevel.ADVANCED_COMPUTER_USER)
    .withMotive(ThreatAgentFactor.Motive.POSSIBLE_REWARD)
    .withOpportunity(ThreatAgentFactor.Opportunity.SOME_ACCESS_OR_RESOURCES_REQUIRED)
    .withSize(ThreatAgentFactor.Size.AUTHENTICATED_USERS)
    .withEaseOfDiscovery(VulnerabilityFactor.EaseOfDiscovery.DIFFICULT)
    .withEaseOfExploit(VulnerabilityFactor.EaseOfExploit.THEORETICAL)
    .withAwareness(VulnerabilityFactor.Awareness.HIDDEN)
    .withIntrusionDetection(VulnerabilityFactor.IntrusionDetection.NOT_LOGGED)
    .withLossOfConfidentiality(TechnicalImpactFactor.LossOfConfidentiality.ALL_DATA_DISCLOSED)
    .withLossOfIntegrity(TechnicalImpactFactor.LossOfIntegrity.EXTENSIVE_SERIOUSLY_CORRUPT_DATA)
    .withLossOfAvailability(TechnicalImpactFactor.LossOfAvailability.MINIMAL_SECONDARY_SERVICES_INTERRUPTED)
    .withLossOfAccountability(TechnicalImpactFactor.LossOfAccountability.COMPLETELY_ANONYMOUS)
    .withFinancialDamage(BusinessImpactFactor.FinancialDamage.SIGNIFICANT_EFFECT_ON_ANNUAL_PROFIT)
    .withReputationDamage(BusinessImpactFactor.ReputationDamage.LOSS_OF_MAJOR_ACCOUNTS)
    .withNonCompliance(BusinessImpactFactor.NonCompliance.HIGH_PROFILE_VIOLATION)
    .withPrivacyViolation(BusinessImpactFactor.PrivacyViolation.MILLIONS_OF_PEOPLE);

Score score = riskRating.calculateScore();
Level likelihood = score.getLikelihood();
Level technicalImpact = score.getTechnicalImpact();
Level businessImact = score.getBusinessImpact();
```

Maven Usage
-------------------
OWASP Risk Rating Calculator is available in the Maven Central Repository.

```xml
<dependency>
    <groupId>us.springett</groupId>
    <artifactId>owasp-risk-rating-calculator</artifactId>
    <version>1.0.0</version>
</dependency>
```

Copyright & License
-------------------

OWASP Risk Rating Calculator is Copyright (c) Steve Springett. All Rights Reserved.

All other trademarks are property of their respective owners.

Permission to modify and redistribute is granted under the terms of the [Apache 2.0] license.

  [Apache 2.0]: http://www.apache.org/licenses/LICENSE-2.0.txt
