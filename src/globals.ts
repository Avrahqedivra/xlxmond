/*
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 *  Copyright(c) 2023-25 F4JDN - Jean-Michel Cohen
 *  
*/

export const __BLACK__: string    = '\x1b[0;90m'
export const __RED__: string      = '\x1b[0;91m'
export const __GREEN__: string    = '\x1b[0;92m'
export const __YELLOW__: string   = '\x1b[0;93m'
export const __ORANGE__: string   = '\x1b[38;2;255;165;0m'
export const __BLUE__: string     = '\x1b[0;94m'
export const __MAGENTA__: string  = '\x1b[0;95m'
export const __CYAN__: string     = '\x1b[0;96m'
export const __WHITE__: string    = '\x1b[0;97m'

export const __CLEAR__: string    = '\x1b[2J'
export const __HOME__: string     = '\x1b[2H'
export const __RESET__: string    = '\x1b[0m'

export const __OK__: string       = `${__GREEN__}OK${__RESET__}`
export const __WARNING__: string  = `${__YELLOW__}Warning${__RESET__}`
export const __FAILED__: string   = `${__RED__}Failed${__RESET__}`
