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


import { format } from 'date-fns';
import udp from "node:dgram"
import { Logger } from "./logger.js"
import * as config from "./config.js"
import {
  RECONNECT_DELAY_MS,
  KEEPALIVE_FIRST_DELAY_MS,
  KEEPALIVE_INTERVAL_MS,
  SERVER_SILENCE_TIMEOUT_MS,
  __version__,
} from "./constants.js"
import { TrafficSnapshot } from "./types.js"

/** Resend "hello" at this interval until the server answers for the first time. */
const HELLO_RETRY_MS = 3000

export interface UdpClientOptions {
  logger: Logger | null
  onTrafficUpdate?: (snapshot: TrafficSnapshot, urgent: boolean) => void
}

export class UdpClient {
  public ticker: any = null
  private client: any = null
  private logger: Logger | null
  private reflector: any[] = []
  private stations: any[] = []
  private nodes: any[] = []
  private modules: any[] = []
  private onair: string = ""
  private offair: string = ""
  private talker: any = { "callsign": "", "packet":"", "datatimee": "", "timestamp": 0 }
  private startTimers: ReturnType<typeof setTimeout>[] = []
  private helloTimer: ReturnType<typeof setInterval> | null = null
  private gotFirstMessage: boolean = false
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private lastRx: number = 0
  private onTrafficUpdate?: (snapshot: TrafficSnapshot, urgent: boolean) => void

  constructor(options: UdpClientOptions) {
    this.logger = options.logger
    this.onTrafficUpdate = options.onTrafficUpdate
  }

  /** Send a datagram to the xlxd server. Reconnects on failure. */
  send(data: Buffer): void {
    const client = this.client
    if (!client) return

    try {
      client.send(
        data,
        config.xlx_server_port,
        config.xlx_server_host,
        (error: any) => {
          if (error && this.client === client) {
            this.logger?.error(`udp send failed: ${error}`)
            this.scheduleReconnect()
          }
        },
      )
    } catch (err: any) {
      this.logger?.error(`udp send threw: ${err}`)
      this.scheduleReconnect()
    }
  }

  /** Stop the "hello" retry loop; safe to call repeatedly. */
  private clearHelloTimer(): void {
    if (this.helloTimer) {
      clearInterval(this.helloTimer)
      this.helloTimer = null
    }
  }

  /** Tear down the udp socket and its timers; safe to call repeatedly. */
  stopClient(): void {
    for (const timer of this.startTimers) clearTimeout(timer)
    this.startTimers = []

    this.clearHelloTimer()

    if (this.ticker) {
      clearInterval(this.ticker)
      this.ticker = null
    }

    const client = this.client
    this.client = null

    if (client) {
      client.removeAllListeners()
      client.on("error", () => {})

      try {
        client.close()
      } catch (e) {
        // already closed
      }
    }
  }

  /** Schedule a single reconnect attempt (idempotent while one is pending). */
  scheduleReconnect(): void {
    if (this.reconnectTimer) return

    this.stopClient()

    this.logger?.info(
      `udp connection lost, reconnecting in ${RECONNECT_DELAY_MS / 1000}s`,
    )

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.connectToServer()
    }, RECONNECT_DELAY_MS)
  }

  /** Open the UDP socket to xlxd, wire listeners, and schedule hello / keepalive. */
  connectToServer(): void {
    this.stopClient()

    const client: any = udp.createSocket("udp4")
    this.client = client
    this.lastRx = Date.now()
    this.gotFirstMessage = false

    client.on("message", (buffer: Buffer, info: any) =>
      this.handleServerMessage(buffer, info),
    )

    client.on("error", (err: any) => {
      if (this.client === client) {
        this.logger?.error(`udp socket error: ${err}`)
        this.scheduleReconnect()
      }
    })

    client.on("close", () => {
      if (this.client === client) this.scheduleReconnect()
    })

    this.startTimers.push(
      setTimeout(() => {
        this.logger?.info("sending initial hello")
        this.send(Buffer.from("hello"))

        // a single UDP datagram can get lost: keep saying hello until the server answers
        this.helloTimer = setInterval(() => {
          if (this.gotFirstMessage) {
            this.clearHelloTimer()
            return
          }
          this.logger?.info("no reply from server yet, resending hello")
          this.send(Buffer.from("hello"))
        }, HELLO_RETRY_MS)
      }, 500),
    )

    if (config.__keep_alive__) {
      this.startTimers.push(
        setTimeout(() => {
          this.logger?.info("initializing keep alive")

          this.ticker = setInterval(() => {
            const silentMs = Date.now() - this.lastRx
            if (silentMs > SERVER_SILENCE_TIMEOUT_MS) {
              this.logger?.error(
                `no data from server for ${Math.round(silentMs / 1000)}s, reconnecting`,
              )
              this.scheduleReconnect()
              return
            }

            this.send(Buffer.from("ping"))
          }, KEEPALIVE_INTERVAL_MS)
        }, KEEPALIVE_FIRST_DELAY_MS),
      )
    }
  }

  /** Mask the first three octets of an IPv4 address. Never throws: bad input yields a fully masked address. */
  maskIp(ip: string): string {
    const parts = String(ip).split(".")
    const valid =
      parts.length === 4 &&
      parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)

    if (!valid) {
      this.logger?.error(`invalid IPv4 address received: ${ip}`)
      return "*.*.*.*"
    }
    return `*.*.*.${parts[3]}`
  }

  /** Decode one UDP datagram from xlxd, rebuild traffic snapshot, and notify. */
  private handleServerMessage(buffer: Buffer, info: any): void {
    let callsign: string = ""
    let OnModule: string = " "
    let entry: any = null

    this.lastRx = Date.now()

    if (!this.gotFirstMessage) {
      this.gotFirstMessage = true
      this.clearHelloTimer()
    }

    if (config.__loginfo__) {
      console.log("Data received from server : " + buffer.toString())
      console.log(
        "Received %d bytes from %s:%d\n",
        buffer.length,
        info.address,
        info.port,
      )
    }

    let msg: any

    try {
      msg = JSON.parse(buffer.toString())
    } catch (err: any) {
      this.logger?.error(
        `discarding malformed datagram from ${info.address}:${info.port}: ${err.message}`,
      )
      return
    }

    if (msg === null || typeof msg !== "object") return

    const has = (key: string): boolean =>
      Object.prototype.hasOwnProperty.call(msg, key)

    try {
      // -- update cached state from the message --
      this.onair = ""
      this.offair = ""
      this.talker = { "callsign": "", "packet":"", "datatimee": "", "timestamp": 0 }

      if (has("PING")) {
        this.send(Buffer.from("PONG"))
        console.log("got PING message")
      }

      if (has("reflector")) {
        this.reflector = msg.reflector
        console.log(this.reflector.toString() + " reflector")
      }

      if (has("modules")) {
        this.modules = msg.modules
        console.log(this.modules.toString() + " modules")
      }

      if (has("nodes") && Array.isArray(msg.nodes)) {
        this.nodes = msg.nodes
      }

      if (has("stations") && Array.isArray(msg.stations)) {
        this.stations = msg.stations
      }

      if (has("onair")) {
        this.onair = typeof msg.onair === "string" ? msg.onair : ""
        this.talker = { "callsign": this.onair, packet:"START", "datatimee": format(Date.now(), 'EEEE EEE MMM dd HH:mm:ss yyyy'), "timestamp": Date.now() }
        console.log(this.onair + " on Air")
      } else if (has("offair")) {
        this.offair = typeof msg.offair === "string" ? msg.offair : ""
        this.talker = { "callsign": this.offair, "packet": "END", "datatimee": format(Date.now(), 'EEEE EEE MMM dd HH:mm:ss yyyy'), "timestamp": Date.now() }
        console.log(this.offair + " off Air")
      } 

      // -- rebuild the traffic snapshot --
      const snapshot: TrafficSnapshot = {
        Version: __version__,
        LinkedPeers: {
          Reflector: this.reflector,
          Peer: [],
        },
        LinkedNodes: {
          Reflector: this.reflector,
          Nodes: [],
        },
        HeardUsers: {
          Reflector: this.reflector,
          Station: [],
        },
        onair: this.onair,
        offair: this.offair,
        talker: this.talker,
      }

      // nodes: split into peers (module " ") and linked nodes
      for (let node of this.nodes) {
        callsign = node["callsign"].trim()
        let ip = node["IP"] ? this.maskIp(node["IP"]) : "*.*.*.*"

        entry = {
          Callsign: `${callsign}   ${node["module"]}`,
          IP: ip,
          LinkedModule: node["linkedto"].trim(),
          Protocol: " ",
          ConnectTime: node["time"].trim(),
          LastHeardTime: node["time"].trim(),
        }

        if (node["module"] === " ") {
          entry["Protocol"] = callsign.substring(0, 3)

          const peers: any[] = snapshot.LinkedPeers.Peer

          // a peer is listed once; further modules of the same peer are appended to it
          const existing = peers.find(
            (peer: any) => String(peer["Callsign"]).trim() === callsign,
          )

          if (existing) {
            existing["LinkedModule"] =
              existing["LinkedModule"] + entry["LinkedModule"]
          } else {
            peers.push(entry)
          }
        } else {
          snapshot.LinkedNodes.Nodes.push(entry)
        }
      }

      // stations: heard users with the module of the node they came through
      for (let station of this.stations) {
        callsign = station["callsign"].trim()
        OnModule = " "

        for (let node of this.nodes) {
          if (
            station["node"] == node["callsign"] &&
            station["module"] == node["module"]
          ) {
            OnModule = node["linkedto"]
            break
          }
        }

        // Remove the leading word + space (e.g. "Wednesday ")
        const cleaned = station["time"].replace(/^\S+\s+/, "")
        const delta_ms = Date.now() - new Date(cleaned).getTime()

        entry = {
          Callsign: callsign.trim(),
          Packet: "",
          ViaNode: `${station["node"].trim()} ${station["module"].trim()}`,
          OnModule: OnModule,
          ViaPeer: "",
          LastHeardTime: station["time"].trim(),
        }

        snapshot.HeardUsers.Station.push(entry)
      }

      // START/END transitions must not be coalesced away, everything else is throttled

      const isUrgent = has("onair") || has("offair")
      if (this.onTrafficUpdate) {
        // console.log("Traffic snapshot: " + JSON.stringify(snapshot.talker))
        this.onTrafficUpdate(snapshot, isUrgent)
      }
    } catch (err: any) {
      this.logger?.error(`Error processing server message: ${err}`)
    }
  }

  /** Clean up timers */
  cleanup(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.stopClient()
  }
}
