package org.example.nativesummary.util;

import com.bai.env.funcs.FunctionModelManager;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.exception.CancelledException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

// 那边pcode visitor仅收集一个set的address
// 使用FunctionManager找函数
public class FuncCoverage {

    public static long BASEADDR = 0x100000;

    // if is in noModel mode
    public static boolean isNoModel = false;
    // for whole analysis coverage
    public Set<Address> staticCoverage;
    public Set<Address> coverage;
    public double percentage;
    Set<Function> staticVisitedFunc;
    Set<Address> uncovered;
    // for per-func func coverage
//    public Map<Address, Set<Address>> funcStaticCoverage;
//    public Map<Address, Set<Address>> funcCoverage;
//    public Map<Address, Double> funcPercentage;
    public Map<Function, PerFuncCoverage> funcCoverage;
    FunctionManager mgr; // lookup function by address

    public FuncCoverage(FunctionManager mgr) {
        this.mgr = mgr;
        this.coverage = new HashSet<>();
        this.funcCoverage = new HashMap<>();
        this.staticCoverage = new HashSet<>();
    }

    public void calcStaticCoverage(Function entry, FlatProgramAPI api) {
        staticVisitedFunc = new HashSet<>();
        calcStaticCoverageInternal(entry, api, staticVisitedFunc);
    }

    // recursive calculate static coverage
    public void calcStaticCoverageInternal(Function current, FlatProgramAPI api, Set<Function> visited) {
        if (current.isThunk()) {
            visited.add(current);
            current = current.getThunkedFunction(true);
        }
        if (isNoModel) { // disable model
            // do not enter external function
            if (current.isExternal()) {
                return;
            }
        } else { // enable model
            // do not enter external function
            // keep consistent with PcodeVisitor visit_CALL
            if (current.isExternal() || current.isThunk() ||
                    FunctionModelManager.isFunctionAddressMapped(current.getEntryPoint()) ||
                    FunctionModelManager.isStd(current)) {
                return;
            }
        }
        // add basicblock
        BasicBlockModel bbm = new BasicBlockModel(api.getCurrentProgram());
        // get func coverage
        Set<Address> funcStatic = funcCoverage.computeIfAbsent(current, k -> {return new PerFuncCoverage();}).getStaticCoverage();
        try {
            for (CodeBlock b: bbm.getCodeBlocksContaining(current.getBody(), api.getMonitor())) {
                funcStatic.add(b.getFirstStartAddress());
                staticCoverage.add(b.getFirstStartAddress());
            }
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }

        Set<Function> call_funcs = current.getCalledFunctions(api.getMonitor());
        // recursive
        for (Function func: call_funcs) {
            if (!visited.contains(func)) {
                visited.add(func);
                calcStaticCoverageInternal(func, api, visited);
            }
        }
    }

    public void calcCoverageStatstic() {
        // organize visited address
        for (Address visited: coverage) {
            Function func = mgr.getFunctionContaining(visited);
            if (func == null) continue;
            Set<Address> funcCov = funcCoverage.computeIfAbsent(func, k -> {return new PerFuncCoverage();}).getCoverage();
            funcCov.add(visited);
        }
        // per function coverage
        for (Function func: funcCoverage.keySet()) {
            PerFuncCoverage perFuncCov = funcCoverage.computeIfAbsent(func, k -> {return new PerFuncCoverage();});
            perFuncCov.calcCoverageStatstic();
//            Set<Address> funcStaticCov = perFuncCov.getStaticCoverage();
//            Set<Address> funcCov = perFuncCov.getCoverage();
//            funcCov.retainAll(funcStaticCov);
//            double percentage = ((double) funcCov.size()) / funcStaticCov.size();
//            Set<Address> funcUncovered = new HashSet<>(funcStaticCov); funcUncovered.removeAll(funcCov);
//            Address sampleUncovered = funcUncovered.iterator().next();
//            funcPercentage.put(func, percentage);
        }
        // for whole analysis coverage
        if (staticCoverage.size() == 0) {
            percentage = -1;
            uncovered = new HashSet<>();
        } else {
            coverage.retainAll(staticCoverage);
            percentage = ((double) coverage.size()) / staticCoverage.size();
            uncovered = new HashSet<>(staticCoverage); uncovered.removeAll(coverage);
        }
    }
    public String getCoverageStatsticString() {
        return String.format("%d/%d (%f) in %d funcs, sample uncovered addresses: ", coverage.size(), staticCoverage.size(), percentage, staticVisitedFunc.size())
                + (uncovered.size() > 0 ? uncovered.iterator().next().toString() : "none");
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

    public Map<Function, PerFuncCoverage> getFuncCoverage() {
        return funcCoverage;
    }
}
