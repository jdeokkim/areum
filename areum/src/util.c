/*
    Copyright (c) 2020 jdeokkim

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include "util.h"

/* 형식화된 디버그 메시지를 출력한다. */
void debug(const char *format, ...) {
#ifdef DEBUG
    va_list ap;
    
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
#endif
}

/* 형식화된 로그 메시지를 출력한다. */
void info(const char *format, ...) {
    va_list ap;
    
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}

/* 형식화된 오류 메시지를 출력하고, 프로그램을 종료한다. */
void panic(const char *format, ...) {
    va_list ap;
    
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    
    exit(EXIT_FAILURE);
}

/* 2진수 `bits`에서 1의 개수가 짝수이면 `true`, 홀수이면 `false`를 반환한다. */
bool parity(uint8_t bits) {
    uint8_t result = 0;
    
    while (bits > 0) {
        result += bits & 0x01;
        bits >>= 1;
    }
    
    return (result & 0x01) == 0;
}