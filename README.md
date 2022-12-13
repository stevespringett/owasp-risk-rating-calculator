[![Build Status](https://github.com/stevespringett/owasp-risk-rating-calculator/workflows/Maven%20CI/badge.svg)](https://github.com/stevespringett/owasp-risk-rating-calculator/actions?workflow=Maven+CI)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/fe80f59eee334016b218178bc72e6395)](https://www.codacy.com/app/stevespringett/owasp-risk-rating-calculator?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stevespringett/owasp-risk-rating-calculator&amp;utm_campaign=Badge_Grade)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)][Apache 2.0]

OWASP Risk Rating Calculator
=====================================

OWASP Risk Rating Calculator is a Java library for programmatically calculating OWASP Risk Rating scores.

Compiling
-------------------

> $ mvn clean package

Usage Example
-------------------
```java
OwaspRiskRating riskRating = new OwaspRiskRating()
    .with(ThreatAgentFactor.SkillLevel.ADVANCED_COMPUTER_USER)
    .with(ThreatAgentFactor.Motive.POSSIBLE_REWARD)
    .with(ThreatAgentFactor.Opportunity.SOME_ACCESS_OR_RESOURCES_REQUIRED)
    .with(ThreatAgentFactor.Size.AUTHENTICATED_USERS)
    .with(VulnerabilityFactor.EaseOfDiscovery.DIFFICULT)
    .with(VulnerabilityFactor.EaseOfExploit.THEORETICAL)
    .with(VulnerabilityFactor.Awareness.HIDDEN)
    .with(VulnerabilityFactor.IntrusionDetection.NOT_LOGGED)
    .with(TechnicalImpactFactor.LossOfConfidentiality.ALL_DATA_DISCLOSED)
    .with(TechnicalImpactFactor.LossOfIntegrity.EXTENSIVE_SERIOUSLY_CORRUPT_DATA)
    .with(TechnicalImpactFactor.LossOfAvailability.MINIMAL_SECONDARY_SERVICES_INTERRUPTED)
    .with(TechnicalImpactFactor.LossOfAccountability.COMPLETELY_ANONYMOUS)
    .with(BusinessImpactFactor.FinancialDamage.SIGNIFICANT_EFFECT_ON_ANNUAL_PROFIT)
    .with(BusinessImpactFactor.ReputationDamage.LOSS_OF_MAJOR_ACCOUNTS)
    .with(BusinessImpactFactor.NonCompliance.HIGH_PROFILE_VIOLATION)
    .with(BusinessImpactFactor.PrivacyViolation.MILLIONS_OF_PEOPLE);

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
    <version>1.0.1</version>
</dependency>
```

Copyright & License
-------------------

OWASP Risk Rating Calculator is Copyright (c) Steve Springett. All Rights Reserved.

All other trademarks are property of their respective owners.

Permission to modify and redistribute is granted under the terms of the [Apache 2.0] license.

  [Apache 2.0]: http://www.apache.org/licenses/LICENSE-2.0.txt
