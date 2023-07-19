package org.example.nativesummary.util;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;

import java.util.HashSet;
import java.util.Set;

public class Coverage {

    public Set<Address> staticCoverage;
    public Set<Address> coverage;
    public double percentage;

    public Coverage() {
        this.staticCoverage = new HashSet<>();
        this.coverage = new HashSet<>();
    }

    public void calcStaticCoverage(Function entry, FlatProgramAPI api, Set<Function> visited) {

        BasicBlockModel bbm = new BasicBlockModel(api.getCurrentProgram());
        try {
            for (CodeBlock b: bbm.getCodeBlocksContaining(entry.getBody(), api.getMonitor())) {
                staticCoverage.add(b.getFirstStartAddress());
            }
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
        // 它的CFG完全是每个地址都在里面，没有分基本块，还是算了
        // CFG.getCFG(entry);

        Set<Function> call_funcs = entry.getCalledFunctions(api.getMonitor());
        // recursive
        for (Function func: call_funcs) {
            if (!visited.contains(func)) {
                visited.add(func);
                calcStaticCoverage(func, api, visited);
            }
        }
    }

    public String getCoverageStatstic() {
        coverage.retainAll(staticCoverage);
        percentage = ((double) coverage.size()) / staticCoverage.size();
        Set<Address> uncovered = new HashSet<>(staticCoverage); uncovered.removeAll(coverage);
        return String.format("%d/%d (%f), sample uncovered addresses: ", coverage.size(), staticCoverage.size(), percentage) + (uncovered.size() > 0 ? uncovered.iterator().next().toString() : "none");
    }

    public void visit(Address address) {
        this.coverage.add(address);
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
}
