/*
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the'Software'), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 *  Copyright(c) 2023-26 F4JDN - Jean-Michel Cohen
 *
 */

import * as globals from "./globals.js"
import { Logger } from "./logger.js"
import { __version__ } from "./constants.js"

/** https://manytools.org/hacker-tools/ascii-banner/ (rowan cap font) */
export const printBanner = (logger: Logger | null): void => {
  if (!logger) return

  logger.info(`${globals.__CLEAR__}${globals.__HOME__}`)

  logger.info(
    `${globals.__BLUE__}    dMP dMP dMP     ${globals.__WHITE__}dMP dMP dMMMMMMMMb  .aMMMb  ${globals.__RED__}dMMMMb  dMMMMb `,
  )
  logger.info(
    `${globals.__BLUE__}   dMK.dMP dMP     ${globals.__WHITE__}dMK.dMP dMP"dMP"dMP dMP"dMP ${globals.__RED__}dMP dMP dMP VMP `,
  )
  logger.info(
    `${globals.__BLUE__}  .dMMMK" dMP     ${globals.__WHITE__}.dMMMK" dMP dMP dMP dMP dMP ${globals.__RED__}dMP dMP dMP dMP  `,
  )
  logger.info(
    `${globals.__BLUE__} dMP"AMF dMP     ${globals.__WHITE__}dMP"AMF dMP dMP dMP dMP.aMP ${globals.__RED__}dMP dMP dMP.aMP   `,
  )
  logger.info(
    `${globals.__BLUE__}dMP dMP dMMMMMP ${globals.__WHITE__}dMP dMP dMP dMP dMP  VMMMP" ${globals.__RED__}dMP dMP dMMMMP"    `,
  )

  logger.info(`${globals.__RESET__}`)

  logger.info(
    `\nNDMonitor v${__version__} (c) 2023-26 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>`,
  )
}
