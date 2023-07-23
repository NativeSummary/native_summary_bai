package org.example.nativesummary.util;

import com.google.gson.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.FileWriter;
import java.lang.reflect.Type;
import java.util.Map;

public class Statistics {
    JsonObject stat;
    JsonArray funcs;
    boolean detailed = false;

    public Statistics(boolean detailed) {
        this.detailed = detailed;
        stat = new JsonObject();
        funcs = new JsonArray();
        stat.add("functions", funcs);
    }

    public void addJNI(Function binFunc, org.example.nativesummary.ir.Function irFunc, long time, FuncCoverage cov, boolean isTaskTimeout) {
        JsonObject func = new JsonObject();
        func.addProperty("binary_address", binFunc.getEntryPoint().getOffset());
        func.addProperty("binary_name", binFunc.getName());
        func.addProperty("class", irFunc.clazz);
        func.addProperty("name", irFunc.name);
        func.addProperty("signature", irFunc.signature);
        func.addProperty("time_ms", time);
        func.addProperty("static_block_count", cov.getStaticCoverage().size());
        func.addProperty("coverage_percentage", cov.getPercentage());
        func.addProperty("is_timeout", isTaskTimeout);
        // Coverage
//        JsonArray staticCov = new JsonArray();
//        for(Address addr: cov.getStaticCoverage()) {
//            staticCov.add("0x"+Long.toHexString(addr.getOffset()));
//        }
//        func.add("static_coverage", staticCov);
//        JsonArray cov_ = new JsonArray();
//        for(Address addr: cov.getCoverage()) {
//            cov_.add("0x"+Long.toHexString(addr.getOffset()));
//        }
//        func.add("coverage", cov_);
        if (detailed) {
            JsonObject perFuncCov = new JsonObject();
            for (Map.Entry<Function, PerFuncCoverage> ent: cov.getFuncCoverage().entrySet()) {
                perFuncCov.add(convertAddr(ent.getKey().getEntryPoint()), ent.getValue().toJson());
            }
            func.add("detailed_per_function_coverage", perFuncCov);
        } else {
            JsonObject perFuncCov = new JsonObject();
            for (Map.Entry<Function, PerFuncCoverage> ent: cov.getFuncCoverage().entrySet()) {
                perFuncCov.addProperty(convertAddr(ent.getKey().getEntryPoint()), ent.getValue().getCoverageString());
            }
            func.add("per_function_coverage", perFuncCov);
        }
        funcs.add(func);
    }

    // if mgr == null, not generate addrMap
    public JsonObject getStatistics(long timeout, long total_script_time, FunctionManager mgr) {
        if (detailed) {
            JsonObject addrMap = buildAddrMap(mgr);
            stat.add("function_address_ranges", addrMap);
        }
        stat.addProperty("time_out_s", timeout);
        stat.addProperty("total_script_time", total_script_time);
        return stat;
    }

    private JsonObject buildAddrMap(FunctionManager mgr) {
        JsonObject ret = new JsonObject(); // entry addr -> list[address range]
        for(Function f: mgr.getFunctions(true)) {
            JsonArray addrRanges = new JsonArray();
            for(AddressRange ar: f.getBody()) {
                if (ar.getMaxAddress().getOffset() == ar.getMinAddress().getOffset()) {
                    continue;
                }
                JsonArray addrRange = new JsonArray();
                addrRange.add(ar.getMinAddress().getOffset());
                addrRange.add(ar.getMaxAddress().getOffset());
                addrRanges.add(addrRange);
            }
            if (addrRanges.size() != 0) {
                ret.add(convertAddr(f.getEntryPoint()), addrRanges);
            }
        }
        return ret;
    }

    public void write(FileWriter fileWriter) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        gson.toJson(stat, fileWriter);
    }


    public static String convertAddr(Address addr) {
        if (addr == null) return "null";
        return "0x"+Long.toHexString(addr.getOffset());
    }

    static class AddressDeserializer implements JsonSerializer<Address>
    {
        @Override
        public JsonElement serialize(Address address, Type type, JsonSerializationContext jsonSerializationContext) {
            return new JsonPrimitive(convertAddr(address));
        }
    }
}
