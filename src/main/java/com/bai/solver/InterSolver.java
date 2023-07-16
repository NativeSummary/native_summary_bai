package com.bai.solver;

import com.bai.env.*;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import org.example.nativesummary.util.MyGlobalState;

import java.util.concurrent.TimeoutException;

/**
 * The class for interprocedural analysis.
 */
public class InterSolver {

    private Function entry;
    private boolean isMain;

    /**
     * Constructor for InterSolver
     * @param entry The start point function for interprocedural analysis
     * @param isMain The flag to indicate whether the entry is conventional "main" function
     */
    public InterSolver(Function entry, boolean isMain) {
        this.entry = entry;
        this.isMain = isMain;
    }


    /**
     * The driver function for the interprocedural analysis  
     */
    public void run() throws CancelledException {
        Context mainContext = Context.getEntryContext(entry);

        // is JNI_OnLoad, then set onLoadContext
        if (MyGlobalState.currentJNI.equals(MyGlobalState.onLoad)) {
            MyGlobalState.onLoadContext = mainContext;
        }

        AbsEnv e = MyGlobalState.onLoadEnv == null ? new AbsEnv() : new AbsEnv(MyGlobalState.onLoadEnv);

        mainContext.initContext(e, true);
        int timeout = GlobalState.config.getTimeout();
        if (timeout < 0) {
            try {
                Context.mainLoop(mainContext);
            } catch (TimeoutException ex) {
                Logging.error("Unexpected timeout!");
                throw new RuntimeException(ex);
            }
        } else {
            Context.mainLoopTimeout(mainContext, timeout);
        }
    }

}