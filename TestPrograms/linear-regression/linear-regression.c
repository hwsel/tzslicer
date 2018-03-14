#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "taintgrind.h"

int linreg(int n0, double x0[], double y0[], double *m0, double *b0, double *r0) {

	double sumx1;
	double sumx2;
	double sumxy;
	double sumy1;
	double sumy2;

	double denom;
	int i = 0;
        double temp_num;

        sumx1 = 0.0;
        sumx2 = 0.0;
        sumxy = 0.0;
        sumy1 = 0.0;
        sumy2 = 0.0;

       for ( i = 0; i < n0; i++ ) { 
          sumx1 += x0[i];       
          sumx2 += pow( x0[i] , 2 );  
          sumxy += x0[i] * y0[i];
          sumy1 += y0[i];      
          sumy2 += pow( y0[i] , 2 ); 
          } 

       denom = ( n0 * sumx2 - pow( sumx1 , 2 ) );
       if ( denom == 0 ) {
           *m0 = 0;
           *b0 = 0;
           *r0 = 0;
       }
       else {
       	*m0 = ( n0 * sumxy  -  sumx1 * sumy1 ) / denom;
       	*b0 = ( sumy1 * sumx2  -  sumx1 * sumxy ) / denom;
        temp_num = ( sumx2 - pow( sumx1 , 2 ) / n0 ) * ( sumy2 - pow( sumy1 , 2) / n0 );
        *r0 = ( sumxy - sumx1 * sumy1 / n0 ) / sqrt( temp_num );
       }
       return 0; 
    }
 
void main(int argc, char **argv) {   
    int n0;
    double x0[6] = {1, 2, 4,  5,  10, 20};
    double y0[6] = {4, 6, 12, 15, 34, 68};

    double m0;
    double b0;
    double r0;

    n0 = 6;

    TNT_MAKE_MEM_TAINTED(x0, sizeof(x0));
    TNT_START_PRINT();

    linreg(n0,x0,y0,&m0,&b0,&r0);
 
    TNT_STOP_PRINT();
}
