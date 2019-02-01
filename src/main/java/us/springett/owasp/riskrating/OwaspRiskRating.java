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

import us.springett.owasp.riskrating.factors.BusinessImpactFactor;
import us.springett.owasp.riskrating.factors.TechnicalImpactFactor;
import us.springett.owasp.riskrating.factors.ThreatAgentFactor;
import us.springett.owasp.riskrating.factors.VulnerabilityFactor;

/**
 * @author Steve Springett
 * @since 1.0.0
 */
@SuppressWarnings("unused")
public class OwaspRiskRating {

    private ThreatAgentFactor.SkillLevel skillLevel;
    private ThreatAgentFactor.Motive motive;
    private ThreatAgentFactor.Opportunity opportunity;
    private ThreatAgentFactor.Size size;
    private VulnerabilityFactor.EaseOfDiscovery easeOfDiscovery;
    private VulnerabilityFactor.EaseOfExploit easeOfExploit;
    private VulnerabilityFactor.Awareness awareness;
    private VulnerabilityFactor.IntrusionDetection intrusionDetection;
    private TechnicalImpactFactor.LossOfConfidentiality lossOfConfidentiality;
    private TechnicalImpactFactor.LossOfIntegrity lossOfIntegrity;
    private TechnicalImpactFactor.LossOfAvailability lossOfAvailability;
    private TechnicalImpactFactor.LossOfAccountability lossOfAccountability;
    private BusinessImpactFactor.FinancialDamage financialDamage;
    private BusinessImpactFactor.ReputationDamage reputationDamage;
    private BusinessImpactFactor.NonCompliance nonCompliance;
    private BusinessImpactFactor.PrivacyViolation privacyViolation;

    /**
     * Calculates a OWASP Risk Rating score.
     * @return a Score object
     * @since 1.0.0
     */
    public Score calculateScore() throws MissingFactorException {
        if (skillLevel == null || motive == null || opportunity == null || size == null || easeOfDiscovery == null
                || easeOfExploit == null || awareness == null || intrusionDetection == null
                || lossOfConfidentiality == null || lossOfIntegrity == null || lossOfAvailability == null
                || lossOfAccountability == null || financialDamage == null || reputationDamage == null
                || nonCompliance == null || privacyViolation == null) {

            throw new MissingFactorException();
        }
        double likelihood = (skillLevel.getLikelihood() + motive.getLikelihood() + opportunity.getLikelihood()
                + size.getLikelihood() + easeOfDiscovery.getLikelihood() + easeOfExploit.getLikelihood()
                + awareness.getLikelihood() + intrusionDetection.getLikelihood()) / 8;
        double technicalImpact = (lossOfConfidentiality.getLikelihood() + lossOfIntegrity.getLikelihood()
                + lossOfAvailability.getLikelihood() + lossOfAccountability.getLikelihood()) / 4;
        double businessImpact = (financialDamage.getLikelihood() + reputationDamage.getLikelihood()
                + nonCompliance.getLikelihood() + privacyViolation.getLikelihood()) / 4;
        return new Score(likelihood, technicalImpact, businessImpact);
    }

    public OwaspRiskRating with(final ThreatAgentFactor.SkillLevel skillLevel) {
        this.skillLevel = skillLevel;
        return this;
    }

    public OwaspRiskRating with(final ThreatAgentFactor.Motive motive) {
        this.motive = motive;
        return this;
    }

    public OwaspRiskRating with(final ThreatAgentFactor.Opportunity opportunity) {
        this.opportunity = opportunity;
        return this;
    }

    public OwaspRiskRating with(final ThreatAgentFactor.Size size) {
        this.size = size;
        return this;
    }

    public OwaspRiskRating with(final VulnerabilityFactor.EaseOfDiscovery easeOfDiscovery) {
        this.easeOfDiscovery = easeOfDiscovery;
        return this;
    }

    public OwaspRiskRating with(final VulnerabilityFactor.EaseOfExploit easeOfExploit) {
        this.easeOfExploit = easeOfExploit;
        return this;
    }

    public OwaspRiskRating with(final VulnerabilityFactor.Awareness awareness) {
        this.awareness = awareness;
        return this;
    }

    public OwaspRiskRating with(final VulnerabilityFactor.IntrusionDetection intrusionDetection) {
        this.intrusionDetection = intrusionDetection;
        return this;
    }

    public OwaspRiskRating with(final TechnicalImpactFactor.LossOfConfidentiality lossOfConfidentiality) {
        this.lossOfConfidentiality = lossOfConfidentiality;
        return this;
    }

    public OwaspRiskRating with(final TechnicalImpactFactor.LossOfIntegrity lossOfIntegrity) {
        this.lossOfIntegrity = lossOfIntegrity;
        return this;
    }

    public OwaspRiskRating with(final TechnicalImpactFactor.LossOfAvailability lossOfAvailability) {
        this.lossOfAvailability = lossOfAvailability;
        return this;
    }

    public OwaspRiskRating with(final TechnicalImpactFactor.LossOfAccountability lossOfAccountability) {
        this.lossOfAccountability = lossOfAccountability;
        return this;
    }

    public OwaspRiskRating with(final BusinessImpactFactor.FinancialDamage financialDamage) {
        this.financialDamage = financialDamage;
        return this;
    }

    public OwaspRiskRating with(final BusinessImpactFactor.ReputationDamage reputationDamage) {
        this.reputationDamage = reputationDamage;
        return this;
    }

    public OwaspRiskRating with(final BusinessImpactFactor.NonCompliance nonCompliance) {
        this.nonCompliance = nonCompliance;
        return this;
    }

    public OwaspRiskRating with(final BusinessImpactFactor.PrivacyViolation privacyViolation) {
        this.privacyViolation = privacyViolation;
        return this;
    }
}
