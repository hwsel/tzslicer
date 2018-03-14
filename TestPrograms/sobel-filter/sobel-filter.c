#include <stdlib.h>
#include <string.h>
#include "taintgrind.h"

int rgbToGray(int *rgb, int *gray, int buffer_size) { 
    int g_size;
    int i0;
    int *p_r;
    int *p_g;    
    g_size = buffer_size / 3;
    p_r = rgb;
    p_g = gray;
    for( i0 = 0; i0 < g_size; i0++ ) {
        *p_g = 0.30 * p_r[0] + 0.59 * p_r[1] + 0.11 * p_r[2];
        p_r += 3;
        p_g++;
    }
    return g_size;
}

void makeOpMem(int *buffer, int b_size, int width, int cindex, int *op_mem) {
    int bottom;
    int top;
    int left;
    int right;
    int temp;
    bottom = cindex - width < 0;
    top = cindex + width >= b_size;
    left = cindex % width == 0;
    right = ( cindex + 1 ) % width == 0;
    if ( ! bottom && ! left ) {
        temp = cindex - width - 1;
        op_mem[0] = buffer[temp];
    }
    else {
        op_mem[0] = 0;
    }
    if ( ! bottom ) {
        temp = cindex - width;
        op_mem[1] = buffer[temp];
    }
    else {
        op_mem[1] = 0;
    }
    if ( ! bottom && ! right  ) {
        temp = cindex - width + 1;
        op_mem[2] = buffer[temp];
    }
    else {
        op_mem[2] = 0;
    }
    if ( ! left  ) {
        temp = cindex - 1;
        op_mem[3] = buffer[temp];
    }
    else {
        op_mem[3] = 0;
    }
    op_mem[4] = buffer[cindex];
    if ( ! right ) {
        temp = cindex + 1;
        op_mem[5] = buffer[temp];
    }
    else {
        op_mem[5] = 0;
    }
    if ( ! top && ! left ) {
        temp = cindex + width - 1;
        op_mem[6] = buffer[temp];
    }
    else {
        op_mem[6] = 0;
    }
    if ( ! top ) {
        temp = cindex + width;
        op_mem[7] = buffer[temp];
    }
    else {
        op_mem[7] = 0;
    }
    if ( ! top && ! right ) {
        temp = cindex + width + 1;
        op_mem[8] = buffer[temp];
    }
    else {
        op_mem[8] = 0;
    }
}

int convolution(int *X, int *Y, int c_size) {
    int sum;
    int i0;
    int temp;
    sum = 0;
    for(i0 = 0; i0 < c_size; i0++) {
        temp = c_size - i0 - 1;
        sum += X[i0] * Y[temp];
    }
    return sum;
}

void itConv(int *buffer, int b_size, int width, int *op, int *res) {
    int op_mem[9];
    int i0;
    for(i0 = 0; i0 < b_size; i0++) {
        makeOpMem(buffer, b_size, width, i0, op_mem);
        res[i0] = convolution(op_mem, op, 9);
    }
}

int mySqrt(int number) {
    int a0;
    int b0;
    a0 = number;
    b0 = 1;
    while(a0 > b0) {
        a0 = ( a0 + b0 ) / 2;
        b0 = number / a0;
    }
    return a0;
}

void contour(int *sobel_h, int *sobel_v, int gray_size, int *contour_img) {
    int i0;
    double temp;
    for(i0 = 0; i0 < gray_size; i0++) {
         temp = sobel_h[i0] * sobel_h[i0] + sobel_v[i0] * sobel_v[i0];
         contour_img[i0] = mySqrt(temp);
    }
}

void main(int argc, char **argv) {
    int rgb_size;
    int gray[9];
    int rgb[9] = {11,25,6,33,7,9,13,25,2};
    int sobel_h[] = {-1, 0, 1, -2, 0, 2, -1, 0, 1};
    int sobel_v[] = {1, 2, 1, 0, 0, 0, -1, -2, -1};
    int contour_img[9];
    int sobel_h_res[9];
    int sobel_v_res[9];

    rgb_size = 9 * 3;

    TNT_MAKE_MEM_TAINTED(rgb, sizeof(rgb));
    TNT_START_PRINT();

    int gray_size = rgbToGray(rgb, gray, rgb_size);
    itConv(gray, gray_size, 3, sobel_h, sobel_h_res);
    itConv(gray, gray_size, 3, sobel_v, sobel_v_res);
    contour(sobel_h_res, sobel_v_res, gray_size, contour_img);

    TNT_STOP_PRINT();
}   

