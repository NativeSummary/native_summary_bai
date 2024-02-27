package org.example.nativesummary.env.funcs;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CLibraryFunctions extends JNIFunctionBase {
    // exit memset __aeabi_memcpy
    private static final String[] syms = {"exit", "open", "close", "write", "clock",
            "remove", "usleep", "stat", "access",
//            "fputc", "ungetc", too much taint
            "fopen", "fclose", "fread", "fputs",//"fseek", "ftell", "lseek", "fseeko", "ftello",
            "flock", "opendir", "readdir", "getpid", "getppid", "kill",
            "prctl", "pipe", "fork", "waitpid", "execlp", "raise",
            "puts", "printf", "sprintf", "snprintf", "fprintf", "scanf", "__iso99_scanf", "sscanf", "__iso99_sscanf", "fscanf", "__isoc99_fscanf", "vprintf", "vfprintf",
            "strchr", "strdup",
            "__aeabi_memclr4", "__aeabi_memclr", "__aeabi_memclr8",
            "__vsprintf_chk",
            "eventfd", "poll",
            "bufferevent_socket_new", "bufferevent_new", "curl_easy_setopt", "curl_easy_init"};

    private static final Set<String> staticSymbols = new HashSet<>(List.of(syms));

    public static final String[] syms2 = {"bufferevent_socket_new", "bufferevent_new", "curl_easy_setopt", "curl_easy_init"};
    public static final Set<String> nonExternals = new HashSet<>(List.of(syms2));

    // not print warning when symbols are not modeled
    // because these functions is not helpful to dataflow analysis, and is too verbose.
    private static final String[] symsNoModel = {"__stack_chk_fail",
            "fseek", "ftell", "lseek", "fseeko", "ftello",
            };
    public static final Set<String> noModelSymbols = new HashSet<>(List.of(symsNoModel));

    public CLibraryFunctions() {
        super(staticSymbols);
    }

    public static CLibraryFunctions instance = new CLibraryFunctions();

    public static CLibraryFunctions getInstance() {
        return instance;
    }
}
