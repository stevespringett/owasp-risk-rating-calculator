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
 * Technical impact can be broken down into factors aligned with the traditional security areas of concern:
 * confidentiality, integrity, availability, and accountability. The goal is to estimate the magnitude of
 * the impact on the system if the vulnerability were to be exploited.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@SuppressWarnings("unused")
public class TechnicalImpactFactor {

    private TechnicalImpactFactor() {
    }

    /**
     * How much data could be disclosed and how sensitive is it?
     */
    public enum LossOfConfidentiality implements ILikelihood {
        MINIMAL_NON_SENSITIVE_DATA_DISCLOSED(2),
        MINIMAL_CRITICAL_DATA_DISCLOSED(6),
        EXTENSIVE_NON_SENSITIVE_DATA_DISCLOSED(6),
        EXTENSIVE_CRITICAL_DATA_DISCLOSED (7),
        ALL_DATA_DISCLOSED(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        LossOfConfidentiality(double likelihood) {
            this.likelihood = likelihood;
        }

        public static LossOfConfidentiality fromDouble(double level) {
            for (LossOfConfidentiality lossOfConfidentiality : values()) {
                if (lossOfConfidentiality.likelihood == level) {
                    return lossOfConfidentiality;
                }
            }
            return null;
        }

        public static LossOfConfidentiality fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * How much data could be corrupted and how damaged is it?
     */
    public enum LossOfIntegrity implements ILikelihood {
        MINIMAL_SLIGHTLY_CORRUPT_DATA(1),
        MINIMAL_SERIOUSLY_CORRUPT_DATA(3),
        EXTENSIVE_SLIGHTLY_CORRUPT_DATA(5),
        EXTENSIVE_SERIOUSLY_CORRUPT_DATA(7),
        ALL_DATA_TOTALLY_CORRUPT(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        LossOfIntegrity(double likelihood) {
            this.likelihood = likelihood;
        }

        public static LossOfIntegrity fromDouble(double level) {
            for (LossOfIntegrity lossOfIntegrity : values()) {
                if (lossOfIntegrity.likelihood == level) {
                    return lossOfIntegrity;
                }
            }
            return null;
        }

        public static LossOfIntegrity fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * How much service could be lost and how vital is it?
     */
    public enum LossOfAvailability implements ILikelihood {
        MINIMAL_SECONDARY_SERVICES_INTERRUPTED(1),
        MINIMAL_PRIMARY_SERVICES_INTERRUPTED(5),
        EXTENSIVE_SECONDARY_SERVICES_INTERRUPTED(5),
        EXTENSIVE_PRIMARY_SERVICES_INTERRUPTED(7),
        ALL_SERVICES_COMPLETELY_LOST(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        LossOfAvailability(double likelihood) {
            this.likelihood = likelihood;
        }

        public static LossOfAvailability fromDouble(double level) {
            for (LossOfAvailability lossOfAvailability : values()) {
                if (lossOfAvailability.likelihood == level) {
                    return lossOfAvailability;
                }
            }
            return null;
        }

        public static LossOfAvailability fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * Are the threat agents' actions traceable to an individual?
     */
    public enum LossOfAccountability implements ILikelihood {
        FULLY_TRACEABLE(1),
        POSSIBLY_TRACEABLE(7),
        COMPLETELY_ANONYMOUS(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        LossOfAccountability(double likelihood) {
            this.likelihood = likelihood;
        }

        public static LossOfAccountability fromDouble(double level) {
            for (LossOfAccountability lossOfAccountability : values()) {
                if (lossOfAccountability.likelihood == level) {
                    return lossOfAccountability;
                }
            }
            return null;
        }

        public static LossOfAccountability fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }
}
