#include <stdio.h>
#include "taintgrind.h" 

int** multiplication(int m, int n, int p, int q, int first[m][n], int second[p][q]) { 
  int c;
  int d;
  int k;
  int sum = 0;
  int multiply[10][10];
 
  if (n != p) {
    multiply[0][0] = -1;
  }
  else {
    for ( c = 0; c < m; c++ ) {
      for ( d = 0; d < q; d++ ) {
        for ( k = 0; k < p; k++ ) {
          sum = sum + first[ c ][ k ] * second[ k ][ d ];
        }
 
        multiply[ c ][ d ] = sum;
        sum = 0;
      }
    }
 
    }
 
  return multiply;
}

void main(int argc, char **argv) {
    int first[1][3] = {1, 2, 3};
    int second[3][1] = {{2}, {3}, {4}};

    int m;
    int n;
    int p;
    int q;

    m = 1;
    n = 3;
    p = 3;
    q = 1;

    TNT_MAKE_MEM_TAINTED(first, sizeof(first));
    TNT_START_PRINT();

    multiplication(m, n, p, q, first, second);

    TNT_STOP_PRINT();
}
