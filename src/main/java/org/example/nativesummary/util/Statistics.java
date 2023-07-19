package org.example.nativesummary.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonWriter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.FileWriter;

public class Statistics {
    JsonObject stat;
    JsonArray funcs;

    public Statistics() {
        stat = new JsonObject();
        funcs = new JsonArray();
        stat.add("functions", funcs);
    }

    public void addJNI(Function binFunc, org.example.nativesummary.ir.Function irFunc, long time, Coverage cov, boolean isTaskTimeout) {
        JsonObject func = new JsonObject();
        func.addProperty("binary_address", binFunc.getEntryPoint().getOffset());
        func.addProperty("binary_name", binFunc.getName());
        func.addProperty("class", irFunc.clazz);
        func.addProperty("name", irFunc.name);
        func.addProperty("signature", irFunc.signature);
        func.addProperty("time_ms", time);
        func.addProperty("coverage_percentage", cov.getPercentage());
        func.addProperty("is_timeout", isTaskTimeout);
        // Coverage
        JsonArray staticCov = new JsonArray();
        for(Address addr: cov.getStaticCoverage()) {
            staticCov.add(addr.getOffset());
        }
        func.add("static_coverage", staticCov);
        JsonArray cov_ = new JsonArray();
        for(Address addr: cov.getCoverage()) {
            cov_.add(addr.getOffset());
        }
        func.add("coverage", cov_);

        funcs.add(func);
    }

    public JsonObject getStatistics(long timeout, long total_script_time) {
        stat.addProperty("time_out_s", timeout);
        stat.addProperty("total_script_time", total_script_time);
        return stat;
    }

    public void write(FileWriter fileWriter) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        gson.toJson(stat, fileWriter);
    }
}
