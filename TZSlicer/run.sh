gcc -I ../valgrind-3.12.0/taintgrind/ -I ../valgrind-3.12.0/include/ -g $1/$1.c -o $1/$1
../valgrind-3.12.0/inst/bin/valgrind --tool=taintgrind $1/$1 2> $1/$1.txt 
python Main.py $1 $2 $3 $4 $5
