package org.example.nativesummary.util;

import com.google.gson.*;
import ghidra.program.model.address.Address;

import java.util.HashSet;
import java.util.Set;

public class PerFuncCoverage {
    Set<Address> staticCoverage;
    Set<Address> coverage;
    Set<Address> uncovered;
    double percentage;
    String SampleUncovered;

    public PerFuncCoverage() {
        this.staticCoverage = new HashSet<>();
        this.coverage = new HashSet<>();
    }

    // calc percentage, uncovered, SampleUncovered
    public void calcCoverageStatstic() {
        if (staticCoverage.size() == 0) { // not statically viable but visited in analysis
            percentage = -1;
            uncovered = new HashSet<>();
            SampleUncovered = null;
        } else {
            coverage.retainAll(staticCoverage);
            percentage = ((double) coverage.size()) / staticCoverage.size();
            uncovered = new HashSet<>(staticCoverage); uncovered.removeAll(coverage);
            SampleUncovered = uncovered.size() > 0 ? Statistics.convertAddr(uncovered.iterator().next()) : null;
        }
    }

    public String getCoverageString() {
        return String.format("%d/%d block (%f)", coverage.size(), staticCoverage.size(), percentage)
                + (percentage == 1.0 ? "" : ", sample uncovered addresses: "+SampleUncovered) ;
    }

    public Set<Address> getStaticCoverage() {
        return staticCoverage;
    }

    public Set<Address> getCoverage() {
        return coverage;
    }

    public double getPercentage() {
        return percentage;
    }

    public JsonElement toJson() {
        Gson gson = new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .registerTypeAdapter(Address.class, new Statistics.AddressDeserializer())
                .create();
        return gson.toJsonTree(this);
//        JsonObject ret = new JsonObject();
//        ret.addProperty("sta", percentage);
//        ret.addProperty("percentage", percentage);
//        return ret;
    }
}
