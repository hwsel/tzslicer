#include <stdio.h>
#include <stdlib.h>

#include "taintgrind.h"

void daxpy_r(int n0, double da, double *dx, int incx, double *dy, int incy) {
  int i0;
  int ix;
  int iy;

  if ( n0 <= 0 ) {
    return;
  }
  if ( da == 0 ) {
    return;
  }
  if ( incx != 1 || incy != 1 ) {
    ix = 1;
    iy = 1;
    if ( incx < 0 ) {
      ix = ( - n0 + 1 ) * incx + 1;
    }
    if ( incy < 0 ) {
      iy = ( - n0 + 1 ) * incy + 1;
    }
    ix = ix - incx;
    iy = iy - incy;
    for ( i0 = 0; i0 < n0; i0++ ) {
      ix = ix + incx;
      iy = iy + incy;
      dy[iy] = dy[iy] + da * dx[ix];
    }
    return;
  }
  for ( i0 = 0; i0 < n0; i0++ ) {
    dy[i0] = dy[i0] + da * dx[i0];
  }
}

void main(int argc, char **argv) {
    int n0;
    double da;
    double dx[6] = {1, 2, 4,  5,  10, 20};
    double dy[6] = {4, 6, 12, 15, 34, 68};
    int incx;
    int incy;

    n0 = 6;
    da = 2;
    incx = 2;
    incy = 1;

    TNT_MAKE_MEM_TAINTED(dx, sizeof(dx));
    TNT_START_PRINT();

    daxpy_r(n0, da, dx, incx, dy, incy);
 
    TNT_STOP_PRINT();
}
