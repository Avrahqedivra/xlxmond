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

import { WebSocketServer } from "ws"
import { Logger } from "./logger.js"
import * as config from "./config.js"
import * as globals from "./globals.js"
import { getClientIp, dropSession } from "./auth.js"
import { BROADCAST_MIN_INTERVAL_MS } from "./constants.js"

export interface DashboardWebSocketServerOptions {
  port: number
  logger: Logger | null
  getCurrentTraffic: () => any
  getReflectors: () => any
  getModules: () => any
}

export class DashboardWebSocketServer {
  private server: WebSocketServer | null = null
  private logger: Logger | null
  private port: number
  private getCurrentTraffic: () => any
  private getReflectors: () => any
  private getModules: () => any
  private broadcastTimer: ReturnType<typeof setTimeout> | null = null
  private lastBroadcast: number = 0

  constructor(options: DashboardWebSocketServerOptions) {
    this.port = options.port
    this.logger = options.logger
    this.getCurrentTraffic = options.getCurrentTraffic
    this.getReflectors = options.getReflectors
    this.getModules = options.getModules
  }

  start(): void {
    try {
      this.logger?.info(
        `creating dashboard socket server on port:${this.port}`,
      )

      const server = new WebSocketServer({
        port: this.port,
        perMessageDeflate: {
          zlibDeflateOptions: {
            chunkSize: 1024,
            memLevel: 7,
            level: 3,
          },
          zlibInflateOptions: {
            chunkSize: 10 * 1024,
          },
          clientNoContextTakeover: true,
          serverNoContextTakeover: true,
          serverMaxWindowBits: 10,
          concurrencyLimit: 10,
          threshold: 1024,
        },
      })

      this.server = server

      server.on("error", (err: any) =>
        this.logger?.error(`WebSocketServer error: ${err}`),
      )

      this.logger?.info(
        `dashboard socket server created ${this.port} ${globals.__OK__}\n`,
      )

      server.on("connection", (ws: any, req: any) => {
        let _message: any = {}

        // connection info: page name, saved as extra properties on the socket
        const urlParams = new URLSearchParams(req.url ? req.url.substring(1) : "")
        ws.page = urlParams.get("page") ? urlParams.get("page") : "generic"
        ws.fromPage = true
        ws.connectTime = Date.now()

        const requestip = getClientIp(req.socket)

        // this.logger?.info(`WebSocket connection from page ${ws.page}`)

        // initial packet
        if (ws.fromPage) {
          _message["BIGEARS"] = server.clients.size.toString()
        }

        if (ws.page === "dashboard" || ws.page === "peers") {
          const traffic = this.getCurrentTraffic()
          _message["PACKETS"] = { TRAFFIC: traffic }
        }

        if (ws.page === "reflectors")
          _message["REFLECTORS"] = this.getReflectors()

        if (ws.page === "modules")
          _message["MODULES"] = this.getModules()

        ws.on("error", console.error)

        ws.on("message", (payload: any) => {
          ws.connectTime = Date.now()
          if (config.__loginfo__) this.logger?.info(`command received: ${payload}`)
        })

        ws.on("close", () => {
          if (config.__web_auth__) dropSession(requestip)
        })

        ws.send(JSON.stringify({ CONFIG: _message }))
      })
    } catch (e: any) {
      this.logger?.info(`Error creating WebSocketServer: ${e.toString()}`)
    }
  }

  /**
   * Broadcast current traffic to dashboard clients, throttled by
   * BROADCAST_MIN_INTERVAL_MS unless `force` is set.
   */
  broadcast(trafficSnapshot: any, force: boolean = false): void {
    const server = this.server
    if (!server) return

    const now = Date.now()
    const wait = this.lastBroadcast + BROADCAST_MIN_INTERVAL_MS - now

    if (!force && wait > 0) {
      if (!this.broadcastTimer) {
        this.broadcastTimer = setTimeout(() => {
          this.broadcastTimer = null
          this.broadcast(trafficSnapshot, true)
        }, wait)
      }
      return
    }

    if (this.broadcastTimer) {
      clearTimeout(this.broadcastTimer)
      this.broadcastTimer = null
    }

    this.lastBroadcast = now

    let payload: string | null = null

    server.clients.forEach((ws: any) => {
      if (
        ws.fromPage &&
        (ws.page === "dashboard" || ws.page === "peers") &&
        ws.readyState === 1
      ) {
        if (payload === null) {
          payload = JSON.stringify({
            TRAFFIC: trafficSnapshot,
            BIGEARS: server.clients.size,
          })
        }

        ws.send(payload, (err: any) => {
          if (err) this.logger?.error(`dashboard send failed: ${err}`)
        })
      }
    })
  }

  getClientCount(): number {
    return this.server?.clients.size ?? 0
  }

  close(): void {
    if (this.broadcastTimer) {
      clearTimeout(this.broadcastTimer)
      this.broadcastTimer = null
    }
    try {
      this.server?.close()
    } catch {}
    this.server = null
  }
}
