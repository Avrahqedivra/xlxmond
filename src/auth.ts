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

import crypto from "crypto"
import * as config from "./config.js"
import * as sessionmgr from "./session.js"
import { Crc16 } from "./crc16.js"
import { sendResponse } from "./http_response.js"
import { SESSION_TTL_MS, TEXT_TYPE } from "./constants.js"

/** HTTP-auth session bookkeeping (last time each ip was seen). */
export const sessionSeen = new Map<string, number>()

/** Normalise a socket remote address to a plain IPv4 string. */
export const getClientIp = (socket: any): string => {
  const address: string =
    socket && socket.remoteAddress ? socket.remoteAddress : ""
  return address.startsWith("::1") ? "127.0.0.1" : address.replace(/^.*:/, "")
}

/** Constant-time string compare. Hash first so both buffers have the same length. */
export const safeEqual = (a: string, b: string): boolean => {
  const ha = crypto.createHash("sha256").update(a).digest()
  const hb = crypto.createHash("sha256").update(b).digest()
  return crypto.timingSafeEqual(ha, hb)
}

/** Create (or refresh) the session entry for an authenticated IP. */
export const touchSession = (ip: string): void => {
  if (!sessionmgr.sessions.hasOwnProperty(ip))
    (sessionmgr.sessions as Record<string, sessionmgr.Session>)[ip] =
      new sessionmgr.Session(ip, 0)

  sessionSeen.set(ip, Date.now())
}

/** Remove a session by IP. */
export const dropSession = (ip: string): void => {
  if (sessionmgr.sessions.hasOwnProperty(ip))
    delete (sessionmgr.sessions as Record<string, sessionmgr.Session>)[ip]

  sessionSeen.delete(ip)
}

/** Sweep idle sessions that have exceeded SESSION_TTL_MS. */
export const sweepExpiredSessions = (): void => {
  const now = Date.now()
  for (const [ip, seen] of sessionSeen) {
    if (now - seen > SESSION_TTL_MS) dropSession(ip)
  }
}

/** Basic-auth check. Sends 401 and returns false on failure; registers the session on success. */
export const authenticate = (req: any, res: any, crc16: Crc16): boolean => {
  const unauthorized = (): boolean => {
    sendResponse(res, 401, TEXT_TYPE, "", {
      "WWW-Authenticate": 'Basic realm="ndmonitor"',
    })
    return false
  }

  const authHeader: string | undefined = req.headers["authorization"]
  if (!authHeader) return unauthorized()

  const [scheme, token] = authHeader.split(" ")

  // anything but a valid Basic credential is rejected
  if (!scheme || scheme.toLowerCase() !== "basic" || !token)
    return unauthorized()

  const decodedData = Buffer.from(token, "base64").toString()
  const separator = decodedData.indexOf(":")
  const username =
    separator === -1 ? decodedData : decodedData.substring(0, separator)
  const password =
    separator === -1 ? "" : decodedData.substring(separator + 1)

  if (
    !safeEqual(
      crc16.compute(username, config.__web_secret_key__).toString(),
      password,
    )
  )
    return unauthorized()

  // authenticated: register the session (swept when idle)
  touchSession(getClientIp(req.socket))
  return true
}
