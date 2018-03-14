# [ARM TrustZone](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.prd29-genc-009492c/index.html)

## Execution Instructions
 - Install [Xilinx Vivado](https://www.xilinx.com/support/download.html).
 - Connect UART and PROG ports of ZedBoard/ZC702 to the PC and turn the board on.
 - To check the uart output from the board, [GTKTerm](http://gtkterm.feige.net/) is the recommended terminal.
   - Go to Configuration in the GTKTerm menu. 
   - Select the correct serial port for the ZedBoard/ZC702 UART (Most likely the port is /dev/ttyACM0 for ZedBoard or /dev/ttyUSB# for ZC702).
   - Set Baud Rate to 115200
 - Download [Sourcery CodeBench](https://www.mentor.com/embedded-software/sourcery-tools/sourcery-codebench/editions/lite-edition/)
 - Put the downloaded CodeSourcery folder into /opt/
 - Set the execution environment:
```
source /<your Xilinx installation directory>/SDK/<your SDK version>/settings64.sh
cd trustzone
sh running.sh
```
The trustzone folder includes a simple demo, which keeps switching between the secure world and the normal world.

## External links
 - [Zynq Design Tutorial](http://svenand.blogdrives.com/archive/160.html#.Wql2f5PwbOQ)
