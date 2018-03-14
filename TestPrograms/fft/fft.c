#include "taintgrind.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int FFT(int dir, int m, double *x0, double *y0) {
   int n;
   int i0 = 0;
   int i1;
   int j;
   int k;
   int i2;
   int l0;
   int l1;
   int l2;
   double c1;
   double c2;
   double tx;
   double ty;
   double t1;
   double t2;
   double u1;
   double u2;
   double z;
   double res;

   n = 1;
   for ( i0 = 0; i0 < m; i0++ ) {
     n = n * 2;
   }
   i2 = n >> 1;
   j = 0;
   for ( i0 = 0; i0 < n - 1; i0++ ) {
     if ( i0 < j ) {
       tx = x0[i0];
       ty = y0[i0];
       x0[i0] = x0[j];
       y0[i0] = y0[j];
       x0[j] = tx;
       y0[j] = ty;
     }
     k = i2;
     while ( k <= j ) {
       j = j - k;
       k = k >> 1;
     }
     j = j + k;
   } 
   c1 = - 1.0; 
   c2 = 0.0;
   l2 = 1;
   for ( l0 = 0; l0 < m; l0++ ) {
      l1 = l2;
      l2 = l2 << 1;
      u1 = 1.0; 
      u2 = 0.0;
      for ( j = 0; j < l1; j++ ) {
         for ( i0 = j; i0 < n; i0 += l2 ) {
            i1 = i0 + l1;
            t1 = u1 * x0[i1] - u2 * y0[i1];
            t2 = u1 * y0[i1] + u2 * x0[i1];
            x0[i1] = x0[i0] - t1; 
            y0[i1] = y0[i0] - t2;
            x0[i0] = x0[i0] + t1;
            y0[i0] = y0[i0] + t2;
         }
         z =  u1 * c1 - u2 * c2;
         u2 = u1 * c2 + u2 * c1;
         u1 = z;
      }
      res = ( 1.0 - c1 ) / 2.0;
      c2 = sqrt(res);
      if ( dir == 1 ) { 
         c2 = - c2;
      }
      res = ( 1.0 + c1 ) / 2.0;
      c1 = sqrt(res);
   }

   if ( dir == 1 ) {
      for ( i0 = 0; i0 < n; i0++ ) {
         x0[i0] = x0[i0] / n;
         y0[i0] = y0[i0] / n;
      }
   }
   
   return 1;
}

void main(int argc, char **argv){
  // Turns on printing
  TNT_START_PRINT();

  int dir;
  int m;
  double x0[8] = {2.0, 3.1, 5.4, 2.5, 7.8, 5.3, 1.2, 9.0};
  double y0[8] = {1.1, 3.8, 7.6, 3.3, 1.6, 4.3, 10.5, 6.9};

  dir = 1;
  m = 3;       

  //Defines int a as tainted
  TNT_MAKE_MEM_TAINTED_NAMED(x0, sizeof(x0),"x0");

  FFT(dir,m,x0,y0);

  // Turns off printing
  TNT_STOP_PRINT();
}
