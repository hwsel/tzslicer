# TZSlicer

## 1 Framework Overview
 - TZSlicer is an C program slicer for hardware isolation [(ARM TrustZone)](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.prd29-genc-009492c/index.html), which processes the sensitive data in the secure world and non-sensitive data in the normal world.

 - TZSlicer includes the following components:
   - Taint Analyzer: using [TaintGrind (v.3.12.0)](https://github.com/wmkhoo/taintgrind)
   - Program Slicer and Slice Optimizer: written in Python (v.3.6.1)


## 2 Execution Instructions
 - Install [TaintGrind (v.3.12.0)](https://github.com/wmkhoo/taintgrind)
 - Execution
```
sh run.sh $NAME_OF_TEST_PROGRAM $SLICE_TYPE1 $SLICE_TYPE2 $OPTIMIZE_TYPE1 $OPTIMIZE_TYPE2
```
   - NAME_OF_TEST_PROGRAM is the file name in the TestPrograms folder
   - SLICE_TYPE1 and SLICE_TYPE2 indicate the slicing method.
     - TZ-M: 0 0
     - TZ-B: 1 0
     - TZ-L: 1 1
   - OPTIMIZE_TYPE1 and OPTIMIZE_TYPE1 indicate the optimization method
     - Disable optimization: 0 0
     - Enable optimization: $x 0
       - x indicates the number of iterations being unrolled
   e.g., to slice the FFT application:
     - TZ-M: sh run.sh fft 0 0 0 0
     - TZ-B: sh run.sh fft 1 0 0 0
     - TZ-L: sh run.sh fft 1 1 0 0
     - TZ-L+(x=2): sh run.sh fft 1 1 2 0
