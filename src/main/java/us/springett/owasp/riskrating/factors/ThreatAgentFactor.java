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
 * This set of factors are related to the threat agent involved. The goal here is to estimate the likelihood
 * of a successful attack by this group of threat agents. Use the worst-case threat agent.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@SuppressWarnings("unused")
public class ThreatAgentFactor {

    private ThreatAgentFactor() {
    }

    /**
     * How technically skilled is this group of threat agents?
     */
    public enum SkillLevel implements ILikelihood {
        NO_TECHNICAL_SKILLS(1),
        SOME_TECHNICAL_SKILLS(3),
        ADVANCED_COMPUTER_USER(5),
        NETWORK_AND_PROGRAMMING_SKILLS(6),
        SECURITY_PENETRATION_SKILLS(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        SkillLevel(double likelihood) {
            this.likelihood = likelihood;
        }

        public static SkillLevel fromDouble(double level) {
            for (SkillLevel skillLevel : values()) {
                if (skillLevel.likelihood == level) {
                    return skillLevel;
                }
            }
            return null;
        }

        public static SkillLevel fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * How motivated is this group of threat agents to find and exploit this vulnerability?
     */
    public enum Motive implements ILikelihood {
        LOW_OR_NO_REWARD(1),
        POSSIBLE_REWARD(4),
        HIGH_REWARD(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        Motive(double likelihood) {
            this.likelihood = likelihood;
        }

        public static Motive fromDouble(double level) {
            for (Motive motive : values()) {
                if (motive.likelihood == level) {
                    return motive;
                }
            }
            return null;
        }

        public static Motive fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * What resources and opportunities are required for this group of threat agents to find and exploit this vulnerability?
     */
    public enum Opportunity implements ILikelihood {
        FULL_ACCESS_OR_EXPENSIVE_RESOURCES_REQUIRED(0),
        SPECIAL_ACCESS_OR_RESOURCES_REQUIRED(4),
        SOME_ACCESS_OR_RESOURCES_REQUIRED(7),
        NO_ACCESS_OR_RESOURCES_REQUIRED(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        Opportunity(double likelihood) {
            this.likelihood = likelihood;
        }

        public static Opportunity fromDouble(double level) {
            for (Opportunity opportunity : values()) {
                if (opportunity.likelihood == level) {
                    return opportunity;
                }
            }
            return null;
        }

        public static Opportunity fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }

    /**
     * How large is this group of threat agents?
     */
    public enum Size implements ILikelihood {
        DEVELOPERS(2),
        SYSTEM_ADMINISTRATORS(2),
        INTRANET_USERS(4),
        PARTNERS(5),
        AUTHENTICATED_USERS(6),
        ANONYMOUS_INTERNET_USERS(9);

        private double likelihood;

        public double getLikelihood() {
            return this.likelihood;
        }
        Size(double likelihood) {
            this.likelihood = likelihood;
        }

        public static Size fromDouble(double level) {
            for (Size size : values()) {
                if (size.likelihood == level) {
                    return size;
                }
            }
            return null;
        }

        public static Size fromString(String level) {
            return fromDouble(Double.valueOf(level));
        }
    }
}
