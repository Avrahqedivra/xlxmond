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
import path from "path"
import crypto from "crypto"

import { WebSocketServer } from "ws"
import udp from "node:dgram"

import http from "http"
import https from "https"

import { parseString } from "xml2js"

import { FileDownloader } from "./filedownloader.js"
import { Logger } from "./logger.js"
import { Crc16 } from "./crc16.js"

import * as config from "./config.js"
import * as globals from "./globals.js"
import * as sessionmgr from "./session.js"

export let __version__: string = "2.0.0"
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

export let logger: Logger | null = null
export let monitor: Monitor | null = null
export let crc16: Crc16 | null = null

// tunables
const SESSION_TTL_MS = 60 * 60 * 1000 // idle HTTP-auth sessions are dropped after 1h
const SESSION_SWEEP_MS = 60 * 1000
const BROADCAST_MIN_INTERVAL_MS = 250 // max dashboard push rate (urgent on/off air bypasses it)
const RECONNECT_DELAY_MS = 5000
const KEEPALIVE_FIRST_DELAY_MS = 15000
const KEEPALIVE_INTERVAL_MS = 20000
const SERVER_SILENCE_TIMEOUT_MS = 120000 // no datagram from xlxd for this long => reconnect
const REFLECTOR_DOWN_AFTER_SECONDS = 24 * 3600 // reflector considered down if last contact is older than this

// system variables
/** Static asset routing table: request extension -> mime type + folder under config.__path__. */
const filetypes: Record<string, { mimetype: string; folder: string }> = {
  ".ico": { mimetype: "image/x-icon", folder: "/images" },
  ".jpg": { mimetype: "image/jpeg", folder: "/images" },
  ".png": { mimetype: "image/png", folder: "/images" },
  ".gif": { mimetype: "image/gif", folder: "/images" },
  ".css": { mimetype: "text/css", folder: "/css" },
  ".mp3": { mimetype: "audio/mp3", folder: "/media" },
  ".mp4": { mimetype: "video/mp4", folder: "/media" },
  ".mpeg": { mimetype: "video/mpeg", folder: "/media" },
  ".ogg": { mimetype: "video/ogg", folder: "/media" },
  ".webm": { mimetype: "video/webm", folder: "/media" },
  ".ppt": { mimetype: "application/vnd.ms-powerpoint", folder: "/media" },
  ".pptx": {
    mimetype:
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    folder: "/media",
  },
  ".js": { mimetype: "text/javascript", folder: "/scripts" },
}

const HTML_TYPE = "text/html; charset=utf-8"
const TEXT_TYPE = "text/plain; charset=utf-8"

// HTTP-auth session bookkeeping (last time each ip was seen)
const sessionSeen = new Map<string, number>()

/** Page templates are static at runtime: read each file once and reuse. */
const templateCache = new Map<string, string>()
const loadTemplate = (filename: string): string => {
  const cached = templateCache.get(filename)
  if (cached !== undefined) return cached
  const data = fs.readFileSync(filename, { encoding: "utf8", flag: "r" })
  templateCache.set(filename, data)
  return data
}

/** Replace every occurrence of `key` with `value` without regex semantics
 *  (so `$&` and friends in the value are not interpreted). */
const replaceAll = (data: string, key: string, value: any): string => {
  // split/join: replaces every occurrence and does not interpret "$&" style patterns in the value
  return data.split(key).join(String(value))
}

/** Expand the `__XXX__` placeholders of a page template.
 *  `mobile` selects the mobile/desktop variant (no global state involved). */
const replaceSystemStrings = (
  data: string,
  mobile: boolean = false,
): string => {
  if (data != null) {
    const replacements: [string, any][] = [
      ["__THEME__", config.__theme__],
      ["__SYSTEM_NAME__", config.__system_name__],
      ["__SITE_LOGO__", __siteLogo_html__],
      ["__VERSION__", __version__],
      ["__FOOTER__", __footer_html__],
      ["__BUTTON_BAR__", __buttonBar_html__],
      ["__SOCKET_SERVER_PORT__", config.__socketServerPort__],
      ["__START_TOT__", config.__start_tot__],
      ["__BANNER_DELAY__", config.__bannerDelay__],
      ["__MOBILE__", mobile],
      ["__MOD_FILTER__", config.__mod_filter__],
      ["__MOD_ORDER__", config.__mod_order__],
      ["__MOD_HILITE__", config.__mod_hilite__],
      ["__MOD_COLORS__", config.__mod_colors__],
      ["__MOD_NUMBER__", config.__mod_number__],
      ["__MOD_NAMES__", config.__mod_names__],
      ["__DYNAMIC_MOD__", config.__dynamic_mod__],
    ]

    for (const [key, value] of replacements) data = replaceAll(data, key, value)
  }

  return data
}

/**
 * the exported lists are only reassigned here and frozen, so importers cannot mutate them
 */
const setReflectorList = (list: any[]): void => {
  __reflectorList__ = Object.freeze(list) as any[]
}

const setDmridList = (list: any[]): void => {
  __dmridList__ = Object.freeze(list) as any[]
}

/**
 * xml2js parses synchronously unless async:true is given; make that explicit and
 * return the result (or throw) so callers never depend on callback ordering
 */
const parseXmlSync = (xml: string, options: any = {}): any => {
  let error: any = null
  let output: any = null

  parseString(xml, { ...options, async: false }, (err: any, result: any) => {
    error = err
    output = result
  })

  if (error) throw error

  return output
}

/** Escape `<`, `>` and `&` inside `<comment>...</comment>` so free-text like
 *  `DStar <> DMR` does not break the XML parser (reflectorlist.xml). */
const sanitizeComments = (xml: string): string => {
  return xml.replace(/<comment>([\s\S]*?)<\/comment>/g, (_, body) => {
    // already CDATA: leave alone
    if (/^\s*<!\[CDATA\[[\s\S]*\]\]>\s*$/.test(body))
      return `<comment>${body}</comment>`
    const escaped = body
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
    return `<comment>${escaped}</comment>`
  })
}

const escapeXml = (text: string): string => {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

/** Normalise a socket remote address to a plain IPv4 string. */
const getClientIp = (socket: any): string => {
  const address: string =
    socket && socket.remoteAddress ? socket.remoteAddress : ""
  return address.startsWith("::1") ? "127.0.0.1" : address.replace(/^.*:/, "")
}

/** Constant-time string compare. Hash first so lengths never leak. */
const safeEqual = (a: string, b: string): boolean => {
  // hash first so both buffers have the same length (no length leak) then compare in constant time
  const ha = crypto.createHash("sha256").update(a).digest()
  const hb = crypto.createHash("sha256").update(b).digest()
  return crypto.timingSafeEqual(ha, hb)
}

/** Create (or refresh) the session entry for an authenticated IP. */
const touchSession = (ip: string): void => {
  if (!sessionmgr.sessions.hasOwnProperty(ip))
    (sessionmgr.sessions as Record<string, sessionmgr.Session>)[ip] =
      new sessionmgr.Session(ip, 0)

  sessionSeen.set(ip, Date.now())
}

/** Remove a session by IP. */
const dropSession = (ip: string): void => {
  if (sessionmgr.sessions.hasOwnProperty(ip))
    delete (sessionmgr.sessions as Record<string, sessionmgr.Session>)[ip]

  sessionSeen.delete(ip)
}

/**
 * single place that writes a complete response, always with a status,
 * Content-Type and Content-Length
 */
const sendResponse = (
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
const error404 = (res: any): void => {
  fs.promises
    .readFile(`${config.__path__}pages/error404.html`)
    .then((content) => sendResponse(res, 404, HTML_TYPE, content))
    .catch(() => sendResponse(res, 404, TEXT_TYPE, "Not found"))
}

/**
 * proxy a qrz.com image; settles on completion, rejects on any error/timeout
 */
const getqrzimage = (url: string, res: any): Promise<void> => {
  return new Promise<void>((resolve, reject) => {
    const request = https.get(url, { timeout: 10000 }, (response: any) => {
      res.writeHead(response.statusCode || 502, {
        "Content-Type":
          response.headers["content-type"] || "application/octet-stream",
      })

      response.on("error", reject)
      response.on("end", () => resolve())
      response.pipe(res)
    })

    request.on("timeout", () =>
      request.destroy(new Error("qrz request timed out")),
    )
    request.on("error", reject)

    // client went away, stop the upstream request
    res.on("close", () => {
      request.destroy()
      resolve()
    })
  })
}

export class Monitor {
  public ticker: any = null
  private client: any = null
  private reflector: any[] = []
  private stations: any[] = []
  private nodes: any[] = []
  private modules: any[] = []
  private onair: any = ""
  private offair: any = ""
  /** Current traffic snapshot pushed to dashboard clients. Always has the
   *  full shape (see emptyTraffic) so the client cannot crash on missing keys. */
  private jsonStr: any = { xlxd: Monitor.emptyTraffic() }
  private dashboardServer: WebSocketServer | null = null
  private webServer: http.Server | null = null
  private dmridMap: Map<string, any> = new Map()
  private startTimers: ReturnType<typeof setTimeout>[] = []
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private broadcastTimer: ReturnType<typeof setTimeout> | null = null
  private sessionSweeper: ReturnType<typeof setInterval> | null = null
  private lastBroadcast: number = 0
  private lastRx: number = 0
  private reflectorListTime: number = Date.now()

  constructor() {
    // requestListener is handed to http.createServer as a bare callback: pin `this`
    this.requestListener = this.requestListener.bind(this)
  }

  /** Empty traffic object with the exact shape the dashboard expects. */
  private static emptyTraffic(): any {
    return {
      Version: __version__,
      LinkedPeers: { Reflector: [], Peer: [] },
      LinkedNodes: { Reflector: [], Nodes: [] },
      HeardUsers: { Reflector: [], Station: [] },
      onair: "",
      offair: "",
    }
  }

  /** Convert the xlxd log file into the dashboard JSON shape and persist it
   *  to `xlxd.json` so a restart can seed the UI before live data arrives. */
  createLogTableJson() {
    let message: any = { xlxd: {} }

    if (!fs.existsSync(config.__xlxdlog_file__)) return message

    try {
      const buffer: string[] = fs
        .readFileSync(config.__xlxdlog_file__)
        .toString("utf-8")
        .split("\n")
      let xmlfixed: string = ""
      let reflector: string = ""

      for (let i = 0; i < buffer.length; i++) {
        let line = buffer[i]

        try {
          if (line.startsWith("<XLX") && reflector == "")
            reflector = line.substring(1, 7)

          line = line
            .replace("<STATION>", "<Station>")
            .replace("</STATION>", "</Station>")
            .replace("<NODE>", "<Nodes>")
            .replace("</NODE>", "</Nodes>")
            .replace("<PEER>", "<Peer>")
            .replace("</PEER>", "</Peer>")
            .replace("<Via peer>", "<ViaPeer>")
            .replace("</Via peer>", "</ViaPeer>")
            .replace("<Via node>", "<ViaNode>")
            .replace("</Via node>", "</ViaNode>")
            .replace("<On module>", "<OnModule>")
            .replace("</On module>", "</OnModule>")
            .replace(
              "<" + reflector + "  heard users>",
              "<HeardUsers><Reflector>" + reflector + "</Reflector>",
            )
            .replace("</" + reflector + "  heard users>", "</HeardUsers>")
            .replace(
              "<" + reflector + "  linked peers>",
              "<LinkedPeers><Reflector>" + reflector + "</Reflector>",
            )
            .replace("</" + reflector + "  linked peers>", "</LinkedPeers>")
            .replace(
              "<" + reflector + "  linked nodes>",
              "<LinkedNodes><Reflector>" + reflector + "</Reflector>",
            )
            .replace("</" + reflector + "  linked nodes>", "</LinkedNodes>")

          if (line.indexOf("</") == -1 || line.startsWith("</")) {
            xmlfixed += line
            if (line.toLowerCase().startsWith("<?xml"))
              xmlfixed = xmlfixed + "<xlxd>"
          } else {
            // parsed synchronously, appended in line order
            const results = parseXmlSync(line)
            const key = Object.keys(results)[0]
            const value = results[key]
            xmlfixed += `<${key}>${typeof value === "string" ? escapeXml(value) : value}</${key}>`
          }
        } catch (err) {
          xmlfixed += line
        }
      }

      xmlfixed += "</xlxd>"

      const parsed = parseXmlSync(xmlfixed, { explicitArray: false })

      if (parsed && typeof parsed.xlxd === "object" && parsed.xlxd !== null)
        message = parsed
    } catch (err: any) {
      logger?.error(`Error parsing ${config.__xlxdlog_file__}: ${err}`)
      return message
    }

    try {
      fs.writeFileSync(
        config.__log_path__ + "xlxd.json",
        JSON.stringify(message, null, 4),
        { encoding: "utf-8", flag: "w" },
      )
    } catch (err: any) {
      logger?.error(`Error writing ${config.__log_path__}xlxd.json: ${err}`)
    }

    return message
  }

  /** Look up a DMR user by callsign (O(1) via dmridMap). */
  getRadioIdRecord(callsign: string) {
    return this.dmridMap.get(callsign) ?? null
  }

  /** Load the subscriber JSON (DMR IDs) and rebuild the lookup map. */
  parseDmrIdList() {
    const file = `${config.__path__}assets/${config.__subscriber_file__}`

    if (!fs.existsSync(file)) {
      logger!.error(`DMR id file ${file} not found`)
      return
    }

    try {
      const users = JSON.parse(
        fs.readFileSync(file, { encoding: "utf8", flag: "r" }),
      ).users

      setDmridList(Array.isArray(users) ? users : [])
      logger!.info(`loaded ${__dmridList__.length} DMR ids`)

      this.dmridMap.clear()
      for (const u of __dmridList__)
        if (u?.callsign) this.dmridMap.set(u.callsign, u)
    } catch (err: any) {
      logger!.error(`Error parsing ${file}: ${err}`)
    }
  }

  /** Parse `reflectorlist.xml` into the global reflector list.
   *  Free-text `<comment>` values are sanitized first, and the file mtime
   *  is remembered to decide "up" vs "down" later. */
  parseXmlReflectorList() {
    const file = `${config.__path__}assets/reflectorlist.xml`

    if (!fs.existsSync(file)) return

    setReflectorList([])

    try {
      const xmldata: string = sanitizeComments(
        fs.readFileSync(file).toString("utf-8"),
      )
      const results = parseXmlSync(xmldata)
      const list = results?.XLXAPI?.answer?.[0]?.reflectorlist?.[0]?.reflector

      if (Array.isArray(list)) setReflectorList(list)

      // "now" for the down/up decision is when the list was produced, not when it is displayed
      this.reflectorListTime = fs.statSync(file).mtimeMs
    } catch (err: any) {
      logger!.error(`Error parsing ${file}: ${err}`)
    }
  }

  /** Serialise the reflector list for the dashboard, normalising uptime to
   *  either "down" or "<n>days". */
  getReflectors() {
    let js: any = []
    const listTimeSec = this.reflectorListTime / 1000

    for (let item of __reflectorList__) {
      const uptimeSeconds: number = parseInt(item["uptime"], 10)
      let lastContact: number = parseInt(item["lastcontact"], 10)

      // tolerate a millisecond timestamp
      if (lastContact > 1e11) lastContact = lastContact / 1000

      // always a string: "down" or "<n>days"
      const down: boolean =
        isNaN(uptimeSeconds) ||
        (!isNaN(lastContact) &&
          listTimeSec - lastContact > REFLECTOR_DOWN_AFTER_SECONDS)

      js.push({
        name: item["name"],
        lastip: item["lastip"],
        dashboardurl: item["dashboardurl"],
        uptime: down
          ? "down"
          : Math.floor(uptimeSeconds / (3600 * 24)) + "days",
        lastcontact: item["lastcontact"],
        country: item["country"],
        comment: item["comment"],
      })
    }

    return js
  }

  /**
   *
   * to be done https://objsal.medium.com/how-to-encode-node-js-response-from-scratch-ce520018d6
   *
   */

  /** Top-level HTTP entry point. Wraps handleRequest so one bad request can
   *  never crash the process. */
  requestListener(req: any, res: any) {
    try {
      this.handleRequest(req, res)
    } catch (err: any) {
      logger!.error(`Unhandled error serving ${req && req.url}: ${err}`)
      if (!res.headersSent)
        sendResponse(res, 500, TEXT_TYPE, "Internal Server Error")
      else res.destroy()
    }
  }

  /** Route a single HTTP request: method + auth checks, qrz proxy, JSON
   *  assets, dynamic pages, static files. */
  private handleRequest(req: any, res: any) {
    // per request, never stored globally
    const userAgent: string = String(req.headers["user-agent"] ?? "")
    const isMobile: boolean = /iPad|Android/.test(userAgent)

    if (isMobile) logger!.info(`mobile phone connection ${userAgent}`)

    const clientIp = getClientIp(req.socket)

    if (config.__web_auth__) {
      const unauthorized = () =>
        sendResponse(res, 401, TEXT_TYPE, "", {
          "WWW-Authenticate": 'Basic realm="ndmonitor"',
        })

      const authHeader: string | undefined = req.headers["authorization"]
      if (!authHeader) return unauthorized()

      const [scheme, token] = authHeader.split(" ")

      // anything but a valid Basic credential is rejected (was: any other scheme skipped the check)
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
          crc16!.compute(username, config.__web_secret_key__).toString(),
          password,
        )
      )
        return unauthorized()

      /**
       * authenticated, add to session (swept when idle) and continue
       */
      touchSession(clientIp)
    }

    const rawUrl: string = String(req.url ?? "/")

    /**
     * qrz.com image proxy
     */
    const qrzIndex = rawUrl.indexOf("https://www.qrz.com/lookup/")
    if (qrzIndex != -1) {
      let target: URL

      try {
        target = new URL(rawUrl.substring(qrzIndex))
      } catch (e) {
        return sendResponse(res, 400, TEXT_TYPE, "Bad request")
      }

      if (target.protocol !== "https:" || target.hostname !== "www.qrz.com")
        return sendResponse(res, 400, TEXT_TYPE, "Bad request")

      getqrzimage(target.toString(), res).catch((err: any) => {
        logger!.error(`qrz image request failed: ${err}`)

        if (!res.headersSent) sendResponse(res, 502, TEXT_TYPE, "Bad gateway")
        else res.destroy()
      })
      return
    }

    // path only (no query/fragment), percent-decoded
    let urlPath: string

    try {
      urlPath = decodeURIComponent(rawUrl.split("?")[0].split("#")[0])
    } catch (e) {
      return sendResponse(res, 400, TEXT_TYPE, "Bad request")
    }

    if (urlPath.indexOf("\0") != -1)
      return sendResponse(res, 400, TEXT_TYPE, "Bad request")

    if (urlPath.toLowerCase().endsWith(".json")) {
      // basename only: no directory components can survive
      const filename: string = path.basename(urlPath)

      // Chrome DevTools probes for a workspace-mapping file; answer 404 quietly.
      if (filename === "com.chrome.devtools.json")
        return sendResponse(res, 404, TEXT_TYPE, "Not found")

      const filepath = path.join(`${config.__path__}assets`, filename)

      if (req.headers["sec-gpc"] === "1") {
        // signal detected, do something
        logger!.info(`gpc request detected`)
      }

      let size: number

      try {
        const st = fs.statSync(filepath)

        if (!st.isFile()) return error404(res)

        size = st.size
      } catch (e) {
        // a missing JSON file is a normal 404, not an application error
        logger!.info(`json file not found: ${filename}`)
        return error404(res)
      }

      const fileStream = fs.createReadStream(filepath)

      fileStream.once("open", () => {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Content-Length": size,
        })
        fileStream.pipe(res)
      })

      // Handle any errors that might occur during streaming
      fileStream.on("error", (err) => {
        logger!.error(`Error reading the file: ${err}`)

        if (!res.headersSent)
          sendResponse(res, 500, TEXT_TYPE, "Internal Server Error")
        else res.destroy()
      })

      res.on("close", () => fileStream.destroy())
      return
    }

    switch (urlPath) {
      case "/":
      case "/index.html":
        return sendResponse(
          res,
          200,
          HTML_TYPE,
          replaceSystemStrings(
            loadTemplate(`${config.__path__}pages/index_template.html`),
            isMobile,
          ),
        )

      case "/reflectors.html":
        return sendResponse(
          res,
          200,
          HTML_TYPE,
          replaceSystemStrings(
            loadTemplate(`${config.__path__}pages${urlPath}`),
            isMobile,
          ),
        )

      default: {
        const ext = path.extname(urlPath).toLowerCase()
        const filetype = Object.prototype.hasOwnProperty.call(filetypes, ext)
          ? filetypes[ext]
          : undefined

        if (!filetype) return error404(res)

        const folder: string = filetype.folder
        const mimetype: string = filetype.mimetype
        const root: string = path.resolve(`${config.__path__}${folder}`)
        let filename: string = urlPath

        // any icon from old apple device
        if (filename.indexOf("apple-touch-icon") != -1)
          filename = "/apple-touch-icon.png"

        let target: string = path.join(root, filename)

        // path traversal guard: the resolved file must stay inside its folder
        if (!target.startsWith(root + path.sep)) return error404(res)

        // if bitmap does not exist return site logo
        if (!fs.existsSync(target)) {
          if (folder === "/images") target = path.join(root, "sitelogo.png")
          else return sendResponse(res, 200, mimetype, "")
        }

        fs.promises
          .readFile(target)
          .then((content) => sendResponse(res, 200, mimetype, content))
          .catch(() => error404(res))
        return
      }
    }
  }

  /** Send a datagram to the xlxd server. Reconnects on failure. */
  send(data: Buffer) {
    //sending msg
    const client = this.client

    if (!client) return

    try {
      client.send(
        data,
        config.xlx_server_port,
        config.xlx_server_host,
        (error: any) => {
          if (error && this.client === client) {
            logger!.error(`udp send failed: ${error}`)
            this.scheduleReconnect()
          }
        },
      )
    } catch (err: any) {
      logger!.error(`udp send threw: ${err}`)
      this.scheduleReconnect()
    }
  }

  /**
   * tear down the udp socket and its timers; safe to call repeatedly
   */
  private stopClient() {
    for (const timer of this.startTimers) clearTimeout(timer)

    this.startTimers = []

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

  /** Graceful shutdown: stop UDP, timers, WebSocket and HTTP servers. */
  async shutdown(): Promise<void> {
    this.stopClient()
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.broadcastTimer) {
      clearTimeout(this.broadcastTimer)
      this.broadcastTimer = null
    }
    if (this.sessionSweeper) {
      clearInterval(this.sessionSweeper)
      this.sessionSweeper = null
    }
    try {
      this.dashboardServer?.close()
    } catch {}
    await new Promise<void>((r) =>
      this.webServer ? this.webServer.close(() => r()) : r(),
    )
  }

  /** Schedule a single reconnect attempt (idempotent while one is pending). */
  private scheduleReconnect() {
    if (this.reconnectTimer) return

    this.stopClient()

    logger!.info(
      `udp connection lost, reconnecting in ${RECONNECT_DELAY_MS / 1000}s`,
    )

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.connectToServer()
    }, RECONNECT_DELAY_MS)
  }

  /**
   * broadcast the current traffic to dashboard clients, at most every
   * BROADCAST_MIN_INTERVAL_MS unless `force` is set
   */
  private broadcast(force: boolean = false) {
    const server = this.dashboardServer

    if (!server) return

    const now = Date.now()
    const wait = this.lastBroadcast + BROADCAST_MIN_INTERVAL_MS - now

    if (!force && wait > 0) {
      // coalesce: the latest state is sent when the timer fires
      if (!this.broadcastTimer) {
        this.broadcastTimer = setTimeout(() => {
          this.broadcastTimer = null
          this.broadcast(true)
        }, wait)
      }
      return
    }

    if (this.broadcastTimer) {
      clearTimeout(this.broadcastTimer)
      this.broadcastTimer = null
    }

    this.lastBroadcast = now

    // serialize once, lazily, only if somebody is listening
    let payload: string | null = null

    server.clients.forEach((ws: any) => {
      if (ws.fromPage && ws.page === "dashboard" && ws.readyState === 1) {
        if (payload === null)
          payload = JSON.stringify({
            TRAFFIC: this.jsonStr["xlxd"],
            BIGEARS: server.clients.size,
          })

        ws.send(payload, (err: any) => {
          if (err) logger!.error(`dashboard send failed: ${err}`)
        })
      }
    })
  }

  /** Decode one UDP datagram from xlxd, rebuild `jsonStr`, and push to dashboards. */
  private handleServerMessage(buffer: Buffer, info: any) {
    let callsign: string = ""
    let OnModule: string = " "
    let entry: any = null

    this.lastRx = Date.now()

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
      logger!.error(
        `discarding malformed datagram from ${info.address}:${info.port}: ${err.message}`,
      )
      return
    }

    if (msg === null || typeof msg !== "object") return

    const has = (key: string): boolean =>
      Object.prototype.hasOwnProperty.call(msg, key)

    try {
      // console.log(JSON.stringify(msg))

      this.onair = ""
      this.offair = ""

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
        // console.log(this.nodes.toString() + " nodes")
      }

      if (has("stations") && Array.isArray(msg.stations)) {
        this.stations = msg.stations
        // console.log(this.stations.toString() + " stations")
      }

      if (has("onair")) {
        this.onair = typeof msg.onair === "string" ? msg.onair : ""
        console.log(this.onair + " on Air")
      }

      if (has("offair")) {
        this.offair = typeof msg.offair === "string" ? msg.offair : ""
        console.log(this.offair + " off Air")
      }

      this.jsonStr = {
        xlxd: {
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
        },
      }

      /**
       * NODES
       */
      for (let item of this.nodes) {
        callsign = item["callsign"].trim()

        entry = {
          Callsign: `${callsign}   ${item["module"]}`,
          IP: "*.*.*.*",
          LinkedModule: item["linkedto"].trim(),
          Protocol: " ",
          ConnectTime: item["time"].trim(),
          LastHeardTime: item["time"].trim(),
        }

        if (item["module"] === " ") {
          entry["Protocol"] = callsign.substring(0, 3)

          const peers: any[] = this.jsonStr["xlxd"]["LinkedPeers"]["Peer"]

          // a peer is listed once; further modules of the same peer are appended to it
          const existing = peers.find(
            (peer: any) => String(peer["Callsign"]).trim() === callsign,
          )

          if (existing)
            existing["LinkedModule"] =
              existing["LinkedModule"] + entry["LinkedModule"]
          else peers.push(entry)
        } else this.jsonStr["xlxd"]["LinkedNodes"]["Nodes"].push(entry)
      }

      for (let item of this.stations) {
        callsign = item["callsign"].trim()
        OnModule = " "

        for (let node of this.nodes) {
          if (
            item["node"] == node["callsign"] &&
            item["module"] == node["module"]
          ) {
            OnModule = node["linkedto"]
            break
          }
        }

        // { 'DATE': REPORT_DATE, 'TIME': REPORT_TIME, 'TYPE': REPORT_TYPE.substring(6), 'PACKET': REPORT_PACKET, 'SYS': REPORT_SYS, 'SRC_ID': REPORT_SRC_ID, 'TS': REPORT_TS, 'TGID': REPORT_TGID, 'ALIAS': REPORT_ALIAS, 'DMRID': REPORT_DMRID, 'CALLSIGN': REPORT_CALLSIGN, 'NAME': REPORT_FNAME, 'DELAY': 0 }

        entry = {
          Callsign: callsign.trim(),
          Packet:
            callsign.trim() == this.onair
              ? "START"
              : callsign.trim() == this.offair
                ? "END"
                : "N/A",
          ViaNode: `${item["node"].trim()} ${item["module"].trim()}`,
          OnModule: OnModule,
          ViaPeer: "",
          LastHeardTime: item["time"].trim(),
        }

        this.jsonStr["xlxd"]["HeardUsers"]["Station"].push(entry)
      }

      // START/END transitions must not be coalesced away, everything else is throttled
      this.broadcast(has("onair") || has("offair"))
    } catch (err: any) {
      logger!.error(`Error processing server message: ${err}`)
    }
  }

  /** Open the UDP socket to xlxd, wire listeners, and schedule hello / keepalive. */
  connectToServer() {
    this.stopClient()

    const client: any = udp.createSocket("udp4") // creating a client socket
    this.client = client
    this.lastRx = Date.now()

    client.on("message", (buffer: Buffer, info: any) =>
      this.handleServerMessage(buffer, info),
    )

    client.on("error", (err: any) => {
      if (this.client === client) {
        logger!.error(`udp socket error: ${err}`)
        this.scheduleReconnect()
      }
    })

    client.on("close", () => {
      if (this.client === client) this.scheduleReconnect()
    })

    this.startTimers.push(
      setTimeout(() => {
        logger!.info("sending initial hello")
        this.send(Buffer.from("hello"))
      }, 500),
    )

    this.startTimers.push(
      setTimeout(() => {
        logger!.info("initializing keep alive")

        this.ticker = setInterval(() => {
          if (Date.now() - this.lastRx > SERVER_SILENCE_TIMEOUT_MS) {
            logger!.error("no data from server, reconnecting")
            this.scheduleReconnect()
            return
          }

          this.send(Buffer.from("ping"))
        }, KEEPALIVE_INTERVAL_MS)
      }, KEEPALIVE_FIRST_DELAY_MS),
    )
  }

  /** Boot sequence: banner, templates, WS + HTTP servers, file download, seed,
   *  then connect to xlxd. */
  init() {
    /**
     * https://manytools.org/hacker-tools/ascii-banner/ (rowan cap font)
     */
    logger!.info(`${globals.__CLEAR__}${globals.__HOME__}`)

    logger!.info(
      `${globals.__BLUE__}    dMP dMP dMP     ${globals.__WHITE__}dMP dMP dMMMMMMMMb  .aMMMb  ${globals.__RED__}dMMMMb  dMMMMb `,
    )
    logger!.info(
      `${globals.__BLUE__}   dMK.dMP dMP     ${globals.__WHITE__}dMK.dMP dMP"dMP"dMP dMP"dMP ${globals.__RED__}dMP dMP dMP VMP `,
    )
    logger!.info(
      `${globals.__BLUE__}  .dMMMK" dMP     ${globals.__WHITE__}.dMMMK" dMP dMP dMP dMP dMP ${globals.__RED__}dMP dMP dMP dMP  `,
    )
    logger!.info(
      `${globals.__BLUE__} dMP"AMF dMP     ${globals.__WHITE__}dMP"AMF dMP dMP dMP dMP.aMP ${globals.__RED__}dMP dMP dMP.aMP   `,
    )
    logger!.info(
      `${globals.__BLUE__}dMP dMP dMMMMMP ${globals.__WHITE__}dMP dMP dMP dMP dMP  VMMMP" ${globals.__RED__}dMP dMP dMMMMP"    `,
    )

    logger!.info(`${globals.__RESET__}`)

    logger!.info(
      `\nNDMonitor v${__version__} (c) 2023-26 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>`,
    )

    // must be first
    __footer_html__ = replaceSystemStrings(
      loadTemplate(`${config.__path__}pages/${config.__footer__}`),
    )

    __siteLogo_html__ = replaceSystemStrings(
      loadTemplate(`${config.__path__}pages/${config.__siteLogo__}`),
    )
    __buttonBar_html__ = replaceSystemStrings(
      loadTemplate(`${config.__path__}pages/${config.__buttonBar__}`),
    )

    /**
     * idle HTTP-auth sessions are removed so the session table cannot grow without bound
     */
    if (config.__web_auth__) {
      this.sessionSweeper = setInterval(() => {
        const now = Date.now()

        for (const [ip, seen] of sessionSeen) {
          if (now - seen > SESSION_TTL_MS) dropSession(ip)
        }
      }, SESSION_SWEEP_MS)

      this.sessionSweeper.unref()
    }

    /**
     * dashboard websocket server
     *
     * create socket server https://github.com/websockets/ws#simple-server
     */
    try {
      logger!.info(
        `creating dashboard socket server on port:${config.__socketServerPort__}`,
      )

      const server = new WebSocketServer({
        port: config.__socketServerPort__,
        perMessageDeflate: {
          zlibDeflateOptions: {
            // See zlib defaults.
            chunkSize: 1024,
            memLevel: 7,
            level: 3,
          },
          zlibInflateOptions: {
            chunkSize: 10 * 1024,
          },
          // Other options settable:
          clientNoContextTakeover: true, // Defaults to negotiated value.
          serverNoContextTakeover: true, // Defaults to negotiated value.
          serverMaxWindowBits: 10, // Defaults to negotiated value.
          // Below options specified as default values.
          concurrencyLimit: 10, // Limits zlib concurrency for perf.
          threshold: 1024, // Size (in bytes) below which messages
          // should not be compressed if context takeover is disabled.
        },
      })

      this.dashboardServer = server

      server.on("error", (err: any) =>
        logger!.error(`WebSocketServer error: ${err}`),
      )

      logger!.info(
        `dashboard socket server created ${config.__socketServerPort__} ${globals.__OK__}\n`,
      )

      server.on("connection", (ws: any, req: any) => {
        let _message: any = {}

        /**
         * get connection information (page name)
         * page name
         *
         * save that into extra properties
         * page
         * fromPage (assume true)
         * connectTime
         */
        const urlParams = new URLSearchParams(req.url.substring(1))
        ws.page = urlParams.get("page") ? urlParams.get("page") : "generic"
        ws.fromPage = true
        ws.connectTime = Date.now()

        // get ip address
        const requestip = getClientIp(req.socket)

        logger!.info(`\nWebSocket connection from page ${ws.page}`)

        // prepare initial packet
        if (ws.fromPage) {
          _message["BIGEARS"] = server.clients.size.toString()
        }

        if (ws.page === "dashboard")
          _message["PACKETS"] = { TRAFFIC: this.jsonStr["xlxd"] }

        if (ws.page === "reflectors")
          _message["REFLECTORS"] = this.getReflectors()

        ws.on("error", console.error)

        ws.on("message", (payload: any) => {
          // update time
          ws.connectTime = Date.now()

          if (config.__loginfo__) logger!.info(`command received: ${payload}`)
        })

        ws.on("close", () => {
          if (config.__web_auth__) dropSession(requestip)
        })

        ws.send(JSON.stringify({ CONFIG: _message }))
      })

      try {
        let hostServer: string = config.__localhost__
        const web = http.createServer(this.requestListener)
        this.webServer = web

        web.on("error", (err: any) => {
          logger!.error(`Web server error: ${err}`)
        })

        web.listen(config.__monitor_webserver_port__, hostServer, () => {
          logger!.info(
            `Web server is running on ${hostServer}:${config.__monitor_webserver_port__}`,
          )
        })
      } catch (e: any) {
        logger!.info(`Error in webserver creation: ${e.toString()}`)
      }
    } catch (e: any) {
      logger!.info(`Error creating WebSocketServer: ${e.toString()}`)
    }

    /**
     * Download files
     */
    const downloader = new FileDownloader()

    const envFiles: any[] = [
      {
        path: `${config.__path__}assets/`,
        file: config.__subscriber_file__,
        url: config.__subscriber_url__,
        stale: config.__file_reload__ * 24 * 3600,
      },
      {
        path: `${config.__path__}assets/`,
        file: config.__reflectors_file__,
        url: config.__reflectors_url__,
        stale: 5 * 24 * 3600,
      },
    ]

    logger!.info(
      "\nStarting files download, be patient, it could take several minutes...",
    )

    downloader
      .downloadAndWriteFiles(envFiles)
      .then(() => {
        logger!.info(`\nAll files downloaded and saved. ${globals.__OK__}`)

        this.parseXmlReflectorList()

        // seed dashboard state from the persisted log so a client that connects
        // before the first UDP datagram renders the last-known traffic

        try {
          const seed = this.createLogTableJson()
          this.jsonStr = {
            xlxd: { ...Monitor.emptyTraffic(), ...(seed?.xlxd ?? {}) },
          }
        } catch (err: any) {
          logger!.error(`could not seed traffic from log: ${err}`)
        }

        this.connectToServer()
        return true
      })
      .catch((err: any) => {
        logger!.error(`File download failed: ${err}`)
        return false
      })
  }
}

logger = new Logger()
crc16 = new Crc16()

monitor = new Monitor()
monitor.init()

const shutdown = () => {
  monitor!.shutdown().finally(() => process.exit(0))
}
process.on("SIGINT", shutdown)
process.on("SIGTERM", shutdown)
