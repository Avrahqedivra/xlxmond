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
 *  Copyright(c) 2023 F4JDN - Jean-Michel Cohen
 *  
*/

// each session contains the username of the user and the time at which it expires
export class Session {
  private _ipaddress_: string = ""
  private _expiresAt_: number = 0

  constructor(ipaddress: string, expiresAt: number) {
      this._ipaddress_ = ipaddress
      this._expiresAt_ = expiresAt
  }

  get ipaddress() : string {
    return this._ipaddress_
  }

  isValid(req: any): boolean {
    return false
  }

  // we'll use this method later to determine if the session has expired
  isExpired(): boolean {
      return this._expiresAt_ < Date.now()
  }
}

// this object stores the users sessions. For larger scale applications, you can use a database or cache for this purpose
export const sessions = {}
