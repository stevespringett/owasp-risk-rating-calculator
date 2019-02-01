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

/**
 * Defines a Score object that defines:
 *  - Threat Agent and Vulnerability (likelihood) score
 *  - Technical Impact score
 *  - Business Impact score
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Score {

    private double likelihoodScore;
    private double technicalImpactScore;
    private double businessImpactScore;

    public Score(double likelihoodScore, double technicalImpactScore, double businessImpactScore) {
        this.likelihoodScore = likelihoodScore;
        this.technicalImpactScore = technicalImpactScore;
        this.businessImpactScore = businessImpactScore;
    }

    public double getLikelihoodScore() {
        return likelihoodScore;
    }

    public double getTechnicalImpactScore() {
        return technicalImpactScore;
    }

    public double getBusinessImpactScore() {
        return businessImpactScore;
    }

    public Level getLikelihood() {
        return rank(likelihoodScore);
    }

    public Level getTechnicalImpact() {
        return rank(technicalImpactScore);
    }

    public Level getBusinessImpact() {
        return rank(businessImpactScore);
    }

    private Level rank(double value) {
        if (value < 3) {
            return Level.LOW;
        } else if (value < 6) {
            return Level.MEDIUM;
        } else {
            return Level.HIGH;
        }
    }
}