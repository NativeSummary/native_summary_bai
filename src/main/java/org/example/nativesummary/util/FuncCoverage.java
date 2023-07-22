package org.example.nativesummary.util;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

// 那边pcode visitor还是仅收集一个set的address
// 后面通过funcMap查到是哪个map，然后放到对应的coverage里面，最后统计出每个函数的覆盖率
// 最后画出dot图
public class FuncCoverage {

    public static long BASEADDR = 0x100000;

    public Map<Address, Set<Address>> funcStaticCoverage;
    public Map<Address, Set<Address>> funcCoverage;
    public Map<Address, Address> addr2Func; // map back from address to func entry address
    public Set<Address> coverage;
    public Map<Address, Double> funcPercentage;
    Set<Function> staticVisited;
    Digraph cg;

    public FuncCoverage(String soName, String jniName) {
        this.funcStaticCoverage = new HashMap<>();
        addr2Func = new HashMap<>();
        this.coverage = new HashSet<>();
        funcPercentage = new HashMap<>();
        cg = new Digraph("CallGraph");
    }

    public void calcStaticCoverage(Function entry, FlatProgramAPI api) {
        staticVisited = new HashSet<>();
        calcStaticCoverageInternal(entry, api, staticVisited);
    }

    // BinAbsInspector的CFG完全是每个地址都在里面，没有分基本块，还是算了
    public void calcStaticCoverageInternal(Function current, FlatProgramAPI api, Set<Function> visited) {
        if (current.isThunk()) {
            visited.add(current);
            current = current.getThunkedFunction(true);
        }
        if (current.isExternal() || current.isThunk()) { // do not enter external function
            return;
        }
        BasicBlockModel bbm = new BasicBlockModel(api.getCurrentProgram());
        // get func coverage
        Set<Address> funcStatic = funcStaticCoverage.computeIfAbsent(current.getEntryPoint(), k -> {return new HashSet<>();});
        try {
            for (CodeBlock b: bbm.getCodeBlocksContaining(current.getBody(), api.getMonitor())) {
                funcStatic.add(b.getFirstStartAddress());
                addr2Func.putIfAbsent(b.getFirstStartAddress(), current.getEntryPoint());
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

    public void getCoverageStatstic() {
        funcCoverage = new HashMap<>();
        for (Address visited: coverage) {
            Address func = addr2Func.get(visited);
            if (func == null) continue;
            Set<Address> funcCov = funcCoverage.computeIfAbsent(func, k -> {return new HashSet<>();});
            funcCov.add(visited);
        }
        for (Address func: funcStaticCoverage.keySet()) {
            Set<Address> funcStaticCov = funcStaticCoverage.computeIfAbsent(func, k -> {return new HashSet<>();});
            Set<Address> funcCov = funcCoverage.computeIfAbsent(func, k -> {return new HashSet<>();});
            funcCov.retainAll(funcStaticCov);
            double percentage = ((double) funcCov.size()) / funcStaticCov.size();
            funcPercentage.put(func, percentage);
        }
    }

    public void visit(Address address) {
        this.coverage.add(address);
    }

//    public Set<Address> getStaticCoverage() {
//        return staticCoverage;
//    }
//
//    public Set<Address> getCoverage() {
//        return coverage;
//    }
//
//    public double getPercentage() {
//        return percentage;
//    }
}
