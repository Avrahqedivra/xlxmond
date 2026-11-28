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

// ─────────────────────────────────────────────────────────────────────────────
// Imports
// ─────────────────────────────────────────────────────────────────────────────

import { format } from 'date-fns';
import { Logger } from "./logger.js"
import { Crc16 } from "./crc16.js"
import * as config from "./config.js"
import { __version__, SESSION_SWEEP_MS } from "./constants.js"
import { TrafficSnapshot } from "./types.js"
import { loadTemplate, replaceSystemStrings } from "./templates.js"
import { sweepExpiredSessions } from "./auth.js"
import { printBanner } from "./banner.js"
import { DataManager } from "./data_manager.js"
import { UdpClient } from "./udp_client.js"
import { DashboardWebSocketServer } from "./websocket_server.js"
import { WebServer } from "./web_server.js"

// ─────────────────────────────────────────────────────────────────────────────
// Exported state (public API)
// ─────────────────────────────────────────────────────────────────────────────

export { __version__ } from "./constants.js"
export let __siteLogo_html__: any = ""
export let __buttonBar_html__: any = ""
export let __footer_html__: any = ""
/**
 * kept for API compatibility. It is no longer written per request (that was a
 * race between concurrent requests); the per-request value is computed locally
 * and passed to replaceSystemStrings().
 */
export let __mobilePhone__: boolean = false
export let __reflectorList__: any[] = []
export let __dmridList__: any[] = []

export let logger: Logger = new Logger()
export let monitor: Monitor | null = null
export let crc16: Crc16 = new Crc16()

// ─────────────────────────────────────────────────────────────────────────────
// Monitor (Orchestrator)
// ─────────────────────────────────────────────────────────────────────────────

export class Monitor {
  private dataManager: DataManager
  private udpClient: UdpClient
  private dashboardServer: DashboardWebSocketServer | null = null
  private webServer: WebServer | null = null
  private sessionSweeper: ReturnType<typeof setInterval> | null = null

  /** Current traffic snapshot pushed to dashboard clients. */
  private jsonStr: any = { xlxd: Monitor.emptyTraffic() }

  constructor() {
    this.requestListener = this.requestListener.bind(this)

    this.dataManager = new DataManager({
      logger,
      onReflectorsUpdated: (list) => {
        __reflectorList__ = list
      },
      onDmridUpdated: (list) => {
        __dmridList__ = list
      },
    })

    this.udpClient = new UdpClient({
      logger,
      onTrafficUpdate: (snapshot: TrafficSnapshot, urgent: boolean) => {
        // When an "onair" message is received from XLXD
        if (urgent) {
          // Re-read and parse xlxd.xml into JSON
          // const logData = this.dataManager.createLogTableJson()

          // Refresh this.jsonStr with the updated log table while keeping active onair
          this.jsonStr = {
            xlxd: {
              ...Monitor.emptyTraffic(),
              ...(snapshot ?? {}),
            },
          }

          // console.log("onair: " + JSON.stringify(this.jsonStr))
            
          // Broadcast the refreshed state immediately to WebSocket clients
          this.dashboardServer?.broadcast(this.jsonStr["xlxd"], urgent)
        }
      },
    })
  }

  get ticker(): any {
    return this.udpClient.ticker
  }

  set ticker(value: any) {
    this.udpClient.ticker = value
  }

  /** Empty traffic object with the exact shape the dashboard expects. */
  public static emptyTraffic(): any {
    return {
      Version: __version__,
      LinkedPeers: { Reflector: [], Peer: [] },
      LinkedNodes: { Reflector: [], Nodes: [] },
      HeardUsers: { Reflector: [], Station: [] },
      onair: "",
      offair: "",
    }
  }

  /** Convert the xlxd log file into the dashboard JSON shape and persist it. */
  createLogTableJson(): any {
    return this.dataManager.createLogTableJson()
  }

  /** Look up a DMR user by callsign. */
  getRadioIdRecord(callsign: string): any {
    return this.dataManager.getRadioIdRecord(callsign)
  }

  /** Load the subscriber JSON (DMR IDs) and rebuild lookup map. */
  parseDmrIdList(): void {
    this.dataManager.parseDmrIdList()
    __dmridList__ = this.dataManager.getDmridList()
  }

  /** Parse `reflectorlist.xml` into the reflector list. */
  parseXmlReflectorList(): void {
    this.dataManager.parseXmlReflectorList()
    __reflectorList__ = this.dataManager.getReflectorList()
  }

  /** Serialise the reflector list for dashboard. */
  getReflectors(): any {
    return this.dataManager.getReflectors()
  }

  getModules(): any {
    return this.dataManager.getModules()
  }

  /** Top-level HTTP entry point delegating to WebServer. */
  requestListener(req: any, res: any): void {
    if (this.webServer) {
      this.webServer.requestListener(req, res)
    }
  }

  /** Send a datagram to the xlxd server. */
  send(data: Buffer): void {
    this.udpClient.send(data)
  }

  /** Open the UDP socket to xlxd and wire listeners. */
  connectToServer(): void {
    this.udpClient.connectToServer()
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  /** Boot sequence: banner, templates, session sweeper, WS + HTTP servers,
   *  data download, then connect to xlxd. */
  init(): void {
    printBanner(logger)

    // footer must be loaded first: the other templates embed it
    __footer_html__ = replaceSystemStrings(
      loadTemplate(`${config.__path__}pages/${config.__footer__}`),
    )
    __siteLogo_html__ = replaceSystemStrings(
      loadTemplate(`${config.__path__}pages/${config.__siteLogo__}`),
    )
    __buttonBar_html__ = replaceSystemStrings(
      loadTemplate(`${config.__path__}pages/${config.__buttonBar__}`),
    )

    // idle HTTP-auth sessions are removed so session table cannot grow unbounded
    if (config.__web_auth__) {
      this.sessionSweeper = setInterval(() => {
        sweepExpiredSessions()
      }, SESSION_SWEEP_MS)

      this.sessionSweeper.unref()
    }

    this.dataManager.scrapModules()
    this.downloadData()
    this.startDashboardServer()
    this.startWebServer()
  }

  private startDashboardServer(): void {
    this.dashboardServer = new DashboardWebSocketServer({
      port: config.__socketServerPort__,
      logger,
      getCurrentTraffic: () => {
        this.jsonStr = this.createLogTableJson()
        return this.jsonStr["xlxd"]
      },
      getReflectors: () => this.getReflectors(),
      getModules: () => this.getModules(),
    })
    this.dashboardServer.start()
  }

  private startWebServer(): void {
    this.webServer = new WebServer({
      port: config.__monitor_webserver_port__,
      host: config.__localhost__,
      logger,
      crc16: crc16 ?? new Crc16(),
      getSiteLogoHtml: () => __siteLogo_html__,
      getButtonBarHtml: () => __buttonBar_html__,
      getFooterHtml: () => __footer_html__,
    })
    this.webServer.start()
  }

  private downloadData(): void {
    this.dataManager
      .downloadData()
      .then(() => {
        try {
          const seed = this.createLogTableJson()
          this.jsonStr = {
            xlxd: { ...Monitor.emptyTraffic(), ...(seed?.xlxd ?? {}) },
          }
        } catch (err: any) {
          logger?.error(`could not seed traffic from log: ${err}`)
        }

        this.connectToServer()
      })
      .catch((err: any) => {
        logger?.error(`Download data error: ${err}`)
      })
  }

  /** Graceful shutdown: stop UDP, timers, WebSocket and HTTP servers. */
  async shutdown(): Promise<void> {
    this.udpClient.cleanup()

    if (this.sessionSweeper) {
      clearInterval(this.sessionSweeper)
      this.sessionSweeper = null
    }

    this.dashboardServer?.close()

    if (this.webServer) {
      await this.webServer.close()
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────────────────────────────────────

logger = new Logger()
crc16 = new Crc16()

monitor = new Monitor()
monitor.init()

const shutdown = () => {
  monitor!.shutdown().finally(() => process.exit(0))
}
process.on("SIGINT", shutdown)
process.on("SIGTERM", shutdown)
