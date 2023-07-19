# Native Summary Project

## interface

the tool is designed to run after preprocessing process. cannot simply run on any `.so` file without special justification.

first preprocessing step (not this repo) will create `<apk_name>.native_summary` folder, containing every `.so` file that need to be analyzed, and a `.funcs.json` file containing static binding resolution results. the `runner.py` is a simple script that call ghidra to analyse the `.so` file and call NativeSummary as a post script. NativeSummary simply use the file path of the file being analyzing and change the suffix to find the json file. and will analysze `JNI_OnLoad` if there is one.

## development process

use runner.py to batch process apks. For each case, use intellij IDEA to debug Ghidira in GUI mode, and load the corresponding project, and manually invoke script, wait for breakpoints.

## setup

+ clone this repo, and init submodule `git submodule update --init`.

+ install ghidra.

+ create `gradle.properties` in project root, and set appropriate properties (on Windows, use `/` or `\\` instead of `\`)

    ```
    org.gradle.java.home = C:\\Program Files\\Java\\jdk-13.0.1
    GHIDRA_INSTALL_DIR=C:/Users/xxx/my_programs/ghidra_10.1.2_PUBLIC
    ```
+ execute build-and-install.sh ( build-and-install.bat on Windows. )

~~Or, use `./gradlew buildExtension -PGHIDRA_INSTALL_DIR=/home/user/programs/ghidra_10.1.2_PUBLIC`~~

### intellij headless debug setup

extracted from Ghidra startup bat file, add echo somewhere to print the java invocation commands.

+ `-cp` select `<no module>`
+ vm options:
  ```
  -XX:ParallelGCThreads=2
  -XX:CICompilerCount=2
  -Duser.home="C:\Users\xxx"
  -Djava.system.class.loader=ghidra.GhidraClassLoader
  -Dfile.encoding=UTF8
  -Duser.country=US
  -Duser.language=en
  -Duser.variant=
  -Dsun.java2d.opengl=false
  -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3
  -Dcpu.core.limit=
  -Dcpu.core.override=
  -Dfont.size.override=
  -Dpython.console.encoding=UTF-8
  -Xshare:off
  --add-opens=java.base/java.lang=ALL-UNNAMED
  --add-opens=java.base/java.util=ALL-UNNAMED
  --add-opens=java.base/java.net=ALL-UNNAMED
  --add-opens=java.desktop/sun.awt.image=ALL-UNNAMED
  -Dsun.java2d.d3d=false
  -Dlog4j.skipJansi=true
  -Xmx2G
  ```
+ Main class: `ghidra.Ghidra`
+ argument:
  ```
  ghidra.app.util.headless.AnalyzeHeadless "C:\Users\xxx\NativeFlowBenchPreAnalysis32\native_complexdata.native_summary\project" "native_summary" -import "C:\Users\xxx\NativeFlowBenchPreAnalysis32\native_complexdata.native_summary\libdata.so" "-postScript" "NativeSummary"
  ```
+ modify classpath -> include: `C:\<where you install ghidra>\ghidra_10.1.2_PUBLIC\Ghidra\Framework\Utility\lib\Utility.jar`

and finally (optional): 

+ before run - external tools - auto-install.bat

intellij will warn about cannot find `ghidra.Ghidra`, you may need to confirm `continue anyway`.

the invocation of ghidra uses `-import`, so will report error (Found conflicting program file) if previous project exists. 
manually delete files in `project/` before each run.


### intellij GUI debug setup

same above, but set cli to `ghidra.GhidraRun`

## limitations

1. multiple lib with inter-dependencies.
1. cannot load string from function's local variable.

### FAQ

1. `> Unable to locate script class: NativeSummary.java` when this error occurs, just delete everything under `"C:\Users\xxx\.ghidra\.ghidra_10.1.2_PUBLIC\osgi\compiled-bundles\"`

### Other useful resources

Thanks to https://github.com/Ayrx/JNIAnalyzer 

### Timeout & Cancel

- `MyGlobalState.isTaskTimeout` controls timeout for single JNI fucntion.
- `MyGlobalState.monitor.checkCanceled()` corresponds to user interface's cancel in GUI mode. In headless mode, the taskmonitor becomes dummy, and this is why we need a seperate flag for timeout.
