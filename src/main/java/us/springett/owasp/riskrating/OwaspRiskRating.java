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

import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Steve Springett
 * @since 1.0.0
 */
@SuppressWarnings("unused")
public class OwaspRiskRating {

    public static final String VECTOR_PATTERN = "SL:\\d/M:\\d/O:\\d/S:\\d/ED:\\d/EE:\\d/A:\\d/ID:\\d/LC:\\d/LI:\\d/LAV:\\d/LAC:\\d/FD:\\d/RD:\\d/NC:\\d/PV:\\d";

    public static final Pattern OWASP_RR_VECTOR_PATTERN = Pattern.compile(VECTOR_PATTERN);

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

    public static OwaspRiskRating fromVector(String vector) {
        if (vector == null) {
            throw new IllegalArgumentException("Null vector provided");
        }
        Matcher vectorMatcher = OWASP_RR_VECTOR_PATTERN.matcher(vector);
        if (vectorMatcher.matches()) {
            String matchedVector = vectorMatcher.group();
            StringTokenizer st = new StringTokenizer(matchedVector, "/");
            OwaspRiskRating result = new OwaspRiskRating();
            result.with(ThreatAgentFactor.SkillLevel.fromString(st.nextElement().toString().split(":")[1]));
            result.with(ThreatAgentFactor.Motive.fromString(st.nextElement().toString().split(":")[1]));
            result.with(ThreatAgentFactor.Opportunity.fromString(st.nextElement().toString().split(":")[1]));
            result.with(ThreatAgentFactor.Size.fromString(st.nextElement().toString().split(":")[1]));
            result.with(VulnerabilityFactor.EaseOfDiscovery.fromString(st.nextElement().toString().split(":")[1]));
            result.with(VulnerabilityFactor.EaseOfExploit.fromString(st.nextElement().toString().split(":")[1]));
            result.with(VulnerabilityFactor.Awareness.fromString(st.nextElement().toString().split(":")[1]));
            result.with(VulnerabilityFactor.IntrusionDetection.fromString(st.nextElement().toString().split(":")[1]));
            result.with(TechnicalImpactFactor.LossOfConfidentiality.fromString(st.nextElement().toString().split(":")[1]));
            result.with(TechnicalImpactFactor.LossOfIntegrity.fromString(st.nextElement().toString().split(":")[1]));
            result.with(TechnicalImpactFactor.LossOfAvailability.fromString(st.nextElement().toString().split(":")[1]));
            result.with(TechnicalImpactFactor.LossOfAccountability.fromString(st.nextElement().toString().split(":")[1]));
            result.with(BusinessImpactFactor.FinancialDamage.fromString(st.nextElement().toString().split(":")[1]));
            result.with(BusinessImpactFactor.ReputationDamage.fromString(st.nextElement().toString().split(":")[1]));
            result.with(BusinessImpactFactor.NonCompliance.fromString(st.nextElement().toString().split(":")[1]));
            result.with(BusinessImpactFactor.PrivacyViolation.fromString(st.nextElement().toString().split(":")[1]));
            return result;
        }
        throw new IllegalArgumentException("Provided vector "+vector+" does not match OWASP RR Vector pattern "+VECTOR_PATTERN);
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

    public ThreatAgentFactor.SkillLevel getSkillLevel() {
        return skillLevel;
    }

    public ThreatAgentFactor.Motive getMotive() {
        return motive;
    }

    public ThreatAgentFactor.Opportunity getOpportunity() {
        return opportunity;
    }

    public ThreatAgentFactor.Size getSize() {
        return size;
    }

    public VulnerabilityFactor.EaseOfDiscovery getEaseOfDiscovery() {
        return easeOfDiscovery;
    }

    public VulnerabilityFactor.EaseOfExploit getEaseOfExploit() {
        return easeOfExploit;
    }

    public VulnerabilityFactor.Awareness getAwareness() {
        return awareness;
    }

    public VulnerabilityFactor.IntrusionDetection getIntrusionDetection() {
        return intrusionDetection;
    }

    public TechnicalImpactFactor.LossOfConfidentiality getLossOfConfidentiality() {
        return lossOfConfidentiality;
    }

    public TechnicalImpactFactor.LossOfIntegrity getLossOfIntegrity() {
        return lossOfIntegrity;
    }

    public TechnicalImpactFactor.LossOfAvailability getLossOfAvailability() {
        return lossOfAvailability;
    }

    public TechnicalImpactFactor.LossOfAccountability getLossOfAccountability() {
        return lossOfAccountability;
    }

    public BusinessImpactFactor.FinancialDamage getFinancialDamage() {
        return financialDamage;
    }

    public BusinessImpactFactor.ReputationDamage getReputationDamage() {
        return reputationDamage;
    }

    public BusinessImpactFactor.NonCompliance getNonCompliance() {
        return nonCompliance;
    }

    public BusinessImpactFactor.PrivacyViolation getPrivacyViolation() {
        return privacyViolation;
    }
}
