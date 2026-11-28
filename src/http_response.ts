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

import fs from "fs"
import * as config from "./config.js"
import { HTML_TYPE, TEXT_TYPE } from "./constants.js"

/** Single place that writes a complete response: status, Content-Type, Content-Length. */
export const sendResponse = (
  res: any,
  status: number,
  contentType: string,
  body: string | Buffer = "",
  headers: Record<string, string | number> = {},
): void => {
  if (res.headersSent) return

  const length = Buffer.isBuffer(body) ? body.length : Buffer.byteLength(body)

  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": length,
    ...headers,
  })
  res.end(body)
}

/** Serve the themed 404 page (plain-text fallback if the file is missing). */
export const error404 = (res: any): void => {
  fs.promises
    .readFile(`${config.__path__}pages/error404.html`)
    .then((content) => sendResponse(res, 404, HTML_TYPE, content))
    .catch(() => sendResponse(res, 404, TEXT_TYPE, "Not found"))
}
