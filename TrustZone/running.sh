cd trustzone/non-secure
make clean
make
cd ..
cp non-secure/normal.elf ./
cd secure
make clean
make
cd ..
cp secure/secure.elf ./
cd ..
cp trustzone/normal.elf ./
cp trustzone/secure.elf ./
xmd -tcl XMD_Commands.tcl
