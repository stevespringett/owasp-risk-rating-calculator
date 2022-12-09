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
package us.springett.owasp.riskrating.factors;

/**
 * The business impact stems from the technical impact, but requires a deep understanding of what is important to
 * the company running the application. In general, you should be aiming to support your risks with business impact,
 * particularly if your audience is executive level. The business risk is what justifies investment in fixing security
 * problems.
 *
 * Many companies have an asset classification guide and/or a business impact reference to help formalize what is
 * important to their business. These standards can help you focus on what's truly important for security. If these
 * aren't available, then it is necessary to talk with people who understand the business to get their take on what's
 * important.
 *
 * The factors below are common areas for many businesses, but this area is even more unique to a company than the
 * factors related to threat agent, vulnerability, and technical impact.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@SuppressWarnings("unused")
public class BusinessImpactFactor {

    private BusinessImpactFactor() {
    }

    /**
     * How much financial damage will result from an exploit?
     */
    public enum FinancialDamage implements ILikelihood {
        LESS_THAN_THE_COST_TO_FIX_THE_VULNERABILITY(1),
        MINOR_EFFECT_ON_ANNUAL_PROFIT(3),
        SIGNIFICANT_EFFECT_ON_ANNUAL_PROFIT(7),
        BANKRUPTCY(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        FinancialDamage(double likelihood) {
            this.likelihood = likelihood;
        }

        public static FinancialDamage fromDouble(double level) {
            for (FinancialDamage financialDamage : values()) {
                if (financialDamage.likelihood == level) {
                    return financialDamage;
                }
            }
            return null;
        }

        public static FinancialDamage fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * Would an exploit result in reputation damage that would harm the business?
     */
    public enum ReputationDamage implements ILikelihood {
        MINIMAL_DAMAGE(1),
        LOSS_OF_MAJOR_ACCOUNTS(4),
        LOSS_OF_GOODWILL(5),
        BRAND_DAMAGE(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        ReputationDamage(double likelihood) {
            this.likelihood = likelihood;
        }

        public static ReputationDamage fromDouble(double level) {
            for (ReputationDamage reputationDamage : values()) {
                if (reputationDamage.likelihood == level) {
                    return reputationDamage;
                }
            }
            return null;
        }

        public static ReputationDamage fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * How much exposure does non-compliance introduce?
     */
    public enum NonCompliance implements ILikelihood {
        MINOR_VIOLATION(2),
        CLEAR_VIOLATION(5),
        HIGH_PROFILE_VIOLATION(7);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        NonCompliance(double likelihood) {
            this.likelihood = likelihood;
        }

        public static NonCompliance fromDouble(double level) {
            for (NonCompliance nonCompliance : values()) {
                if (nonCompliance.likelihood == level) {
                    return nonCompliance;
                }
            }
            return null;
        }

        public static NonCompliance fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * How much personally identifiable information could be disclosed?
     */
    public enum PrivacyViolation implements ILikelihood {
        ONE_INDIVIDUAL(3),
        HUNDREDS_OF_PEOPLE(5),
        THOUSANDS_OF_PEOPLE(7),
        MILLIONS_OF_PEOPLE(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        PrivacyViolation(double likelihood) {
            this.likelihood = likelihood;
        }

        public static PrivacyViolation fromDouble(double level) {
            for (PrivacyViolation privacyViolation : values()) {
                if (privacyViolation.likelihood == level) {
                    return privacyViolation;
                }
            }
            return null;
        }

        public static PrivacyViolation fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }
}
