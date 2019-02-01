/*
 * This file is part of the OWASP Risk Rating Calculator.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.springett.owasp.riskrating;

import org.junit.Assert;
import org.junit.Test;
import us.springett.owasp.riskrating.factors.BusinessImpactFactor;
import us.springett.owasp.riskrating.factors.TechnicalImpactFactor;
import us.springett.owasp.riskrating.factors.ThreatAgentFactor;
import us.springett.owasp.riskrating.factors.VulnerabilityFactor;

public class OwaspRiskRatingTest {

    @Test
    public void calculationTest() throws Exception {
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

        Assert.assertEquals(4.875, score.getLikelihoodScore(), 0);
        Assert.assertEquals(6.5, score.getTechnicalImpactScore(), 0);
        Assert.assertEquals(6.75, score.getBusinessImpactScore(), 0);

        Assert.assertEquals(Level.MEDIUM, score.getLikelihood());
        Assert.assertEquals(Level.HIGH, score.getTechnicalImpact());
        Assert.assertEquals(Level.HIGH, score.getBusinessImpact());
    }
}
