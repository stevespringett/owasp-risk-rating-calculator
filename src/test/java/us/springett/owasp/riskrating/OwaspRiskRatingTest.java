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

        Assert.assertEquals(4.875, score.getLikelihoodScore(), 0);
        Assert.assertEquals(6.5, score.getTechnicalImpactScore(), 0);
        Assert.assertEquals(6.75, score.getBusinessImpactScore(), 0);

        Assert.assertEquals(Level.MEDIUM, score.getLikelihood());
        Assert.assertEquals(Level.HIGH, score.getTechnicalImpact());
        Assert.assertEquals(Level.HIGH, score.getBusinessImpact());
    }

    @Test
    public void vectorParseNominalTest() throws MissingFactorException {
        String vector = "SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3";

        OwaspRiskRating rr = OwaspRiskRating.fromVector(vector);
        Score score = rr.calculateScore();

        Assert.assertEquals(ThreatAgentFactor.SkillLevel.NO_TECHNICAL_SKILLS, rr.getSkillLevel());
        Assert.assertEquals(ThreatAgentFactor.Motive.LOW_OR_NO_REWARD, rr.getMotive());
        Assert.assertEquals(ThreatAgentFactor.Opportunity.FULL_ACCESS_OR_EXPENSIVE_RESOURCES_REQUIRED, rr.getOpportunity());
        Assert.assertEquals(ThreatAgentFactor.Size.DEVELOPERS, rr.getSize());
        Assert.assertEquals(VulnerabilityFactor.EaseOfDiscovery.PRACTICALLY_IMPOSSIBLE, rr.getEaseOfDiscovery());
        Assert.assertEquals(VulnerabilityFactor.EaseOfExploit.THEORETICAL, rr.getEaseOfExploit());
        Assert.assertEquals(VulnerabilityFactor.Awareness.UNKNOWN, rr.getAwareness());
        Assert.assertEquals(VulnerabilityFactor.IntrusionDetection.ACTIVE_DETECTION_IN_APPLICATION, rr.getIntrusionDetection());
        Assert.assertEquals(TechnicalImpactFactor.LossOfConfidentiality.MINIMAL_NON_SENSITIVE_DATA_DISCLOSED, rr.getLossOfConfidentiality());
        Assert.assertEquals(TechnicalImpactFactor.LossOfIntegrity.MINIMAL_SLIGHTLY_CORRUPT_DATA, rr.getLossOfIntegrity());
        Assert.assertEquals(TechnicalImpactFactor.LossOfAvailability.MINIMAL_SECONDARY_SERVICES_INTERRUPTED, rr.getLossOfAvailability());
        Assert.assertEquals(TechnicalImpactFactor.LossOfAccountability.FULLY_TRACEABLE, rr.getLossOfAccountability());
        Assert.assertEquals(BusinessImpactFactor.FinancialDamage.LESS_THAN_THE_COST_TO_FIX_THE_VULNERABILITY, rr.getFinancialDamage());
        Assert.assertEquals(BusinessImpactFactor.ReputationDamage.MINIMAL_DAMAGE, rr.getReputationDamage());
        Assert.assertEquals(BusinessImpactFactor.NonCompliance.MINOR_VIOLATION, rr.getNonCompliance());
        Assert.assertEquals(BusinessImpactFactor.PrivacyViolation.ONE_INDIVIDUAL, rr.getPrivacyViolation());

        Assert.assertEquals(1.0, score.getLikelihoodScore(),0);
        Assert.assertEquals(1.25, score.getTechnicalImpactScore(),0);
        Assert.assertEquals(1.75, score.getBusinessImpactScore(),0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void vectorParseErrorTest() {
        OwaspRiskRating.fromVector("SL:1/M:1/O:0/S:2/ED:1/EE:null/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3");
    }

}
