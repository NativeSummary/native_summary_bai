package org.example.nativesummary.util;

import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

import java.util.Arrays;
import java.util.Objects;

public class JNIValue {
    public static final String PARAM_PREFIX = "Param";
    public long[] callstring = new long[GlobalState.config.getCallStringK()];

    // variant type: an enum indicating which type, and a value for each type
    // to ease implementing equals and hashcode, other unused value must be default value.
    enum JNIValueType {
        PARAM,
        FUNC_CALL
    };
    JNIValueType vty;
    Function api = null; // FUNC_CALL
    int paramInd = -1; // PARAM

    public long callsite;
    public JNIValue(Context ctx, Function api, long callsite) {
        this.vty = JNIValueType.FUNC_CALL;
        this.api = api;
        if (ctx != null) {
            System.arraycopy(ctx.getCallString(), 0, this.callstring, 0, GlobalState.config.getCallStringK());
        }
        this.callsite = callsite;
    }

    // param constructor
    public JNIValue(int index) {
        this.vty = JNIValueType.PARAM;
        this.paramInd = index;
    }

    public boolean isParamValue() {
        return vty == JNIValueType.PARAM;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JNIValue jniValue = (JNIValue) o;
        return paramInd == jniValue.paramInd && callsite == jniValue.callsite && Arrays.equals(callstring, jniValue.callstring) && vty == jniValue.vty && Objects.equals(api, jniValue.api);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(vty, api, paramInd, callsite);
        result = 31 * result + Arrays.hashCode(callstring);
        return result;
    }

    public int getParamInd() {
        if (vty != JNIValueType.PARAM) {
            throw new RuntimeException("JNIValue: call getFunc with invalid type: "+vty);
        }
        return paramInd;
    }
    public Function getFunc() {
        if (vty != JNIValueType.FUNC_CALL) {
            throw new RuntimeException("JNIValue: call getFunc with invalid type: "+vty);
        }
        return api;
    }
}
