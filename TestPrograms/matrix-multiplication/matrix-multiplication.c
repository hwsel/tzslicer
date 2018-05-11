#include <stdio.h>
#include "taintgrind.h" 

int** multiplication(int m0, int n0, int p0, int q0, int first[m0][n0], int second[p0][q0]) { 
  int c0;
  int d0;
  int k0;
  int sum = 0;
  int multiply[10][10];
 
  if (n0 != p0) {
    multiply[0][0] = -1;
  }
  else {
    for ( c0 = 0; c0 < m0; c0++ ) {
      for ( d0 = 0; d0 < q0; d0++ ) {
        for ( k0 = 0; k0 < p0; k0++ ) {
          sum = sum + first[c0][k0] * second[k0][d0];
        }
 
        multiply[c0][d0] = sum;
        sum = 0;
      }
    }
 
    }
 
  return multiply;
}

void main(int argc, char **argv) {
    int first[1][3] = {1, 2, 3};
    int second[3][1] = {{2}, {3}, {4}};

    int m0;
    int n0;
    int p0;
    int q0;

    m0 = 1;
    n0 = 3;
    p0 = 3;
    q0 = 1;

    TNT_MAKE_MEM_TAINTED(first, sizeof(first));
    TNT_START_PRINT();

    multiplication(m0, n0, p0, q0, first, second);

    TNT_STOP_PRINT();
}
