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
import http from "http"
import { Logger } from "./logger.js"
import { Crc16 } from "./crc16.js"
import * as config from "./config.js"
import { HTML_TYPE, TEXT_TYPE, filetypes } from "./constants.js"
import { sendResponse, error404 } from "./http_response.js"
import { authenticate } from "./auth.js"
import { loadTemplate, replaceSystemStrings } from "./templates.js"
import { getqrzimage } from "./get_om_pic.js"

export interface WebServerOptions {
  port: number
  host: string
  logger: Logger | null
  crc16: Crc16
  getSiteLogoHtml: () => string
  getButtonBarHtml: () => string
  getFooterHtml: () => string
}

export class WebServer {
  private server: http.Server | null = null
  private port: number
  private host: string
  private logger: Logger | null
  private crc16: Crc16
  private getSiteLogoHtml: () => string
  private getButtonBarHtml: () => string
  private getFooterHtml: () => string

  constructor(options: WebServerOptions) {
    this.port = options.port
    this.host = options.host
    this.logger = options.logger
    this.crc16 = options.crc16
    this.getSiteLogoHtml = options.getSiteLogoHtml
    this.getButtonBarHtml = options.getButtonBarHtml
    this.getFooterHtml = options.getFooterHtml

    this.requestListener = this.requestListener.bind(this)
  }

  /** Top-level HTTP entry point. Wraps handleRequest so one bad request cannot crash process. */
  requestListener(req: any, res: any): void {
    try {
      this.handleRequest(req, res)
    } catch (err: any) {
      this.logger?.error(`Unhandled error serving ${req && req.url}: ${err}`)
      if (!res.headersSent)
        sendResponse(res, 500, TEXT_TYPE, "Internal Server Error")
      else res.destroy()
    }
  }

  /** Route a single HTTP request: auth, qrz proxy, JSON assets, pages, static files. */
  private handleRequest(req: any, res: any): void {
    const userAgent: string = String(req.headers["user-agent"] ?? "")
    const isMobile: boolean = /iPad|Android/.test(userAgent)

    if (isMobile) this.logger?.info(`mobile phone connection ${userAgent}`)

    if (config.__web_auth__ && !authenticate(req, res, this.crc16)) return

    const rawUrl: string = String(req.url ?? "/")

    // qrz.com image proxy
    const qrzIndex = rawUrl.indexOf("https://www.qrz.com/lookup/")
    if (qrzIndex != -1) return this.proxyQrz(rawUrl.substring(qrzIndex), res)

    // path only (no query/fragment), percent-decoded
    let urlPath: string
    try {
      urlPath = decodeURIComponent(rawUrl.split("?")[0].split("#")[0])
    } catch (e) {
      return sendResponse(res, 400, TEXT_TYPE, "Bad request")
    }

    if (urlPath.indexOf("\0") != -1)
      return sendResponse(res, 400, TEXT_TYPE, "Bad request")

    if (urlPath.toLowerCase().endsWith(".json"))
      return this.serveJson(urlPath, req, res)

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
            this.getSiteLogoHtml(),
            this.getButtonBarHtml(),
            this.getFooterHtml(),
          ),
        )

      case "/modules.html":
      case "/reflectors.html":
      case "/peers.html":
        return sendResponse(
          res,
          200,
          HTML_TYPE,
          replaceSystemStrings(
            loadTemplate(`${config.__path__}pages${urlPath}`),
            isMobile,
            this.getSiteLogoHtml(),
            this.getButtonBarHtml(),
            this.getFooterHtml(),
          ),
        )

      default:
        return this.serveStatic(urlPath, res)
    }
  }

  /** Validate and proxy a qrz.com lookup image. */
  private proxyQrz(url: string, res: any): void {
    let target: URL
    try {
      target = new URL(url)
    } catch (e) {
      return sendResponse(res, 400, TEXT_TYPE, "Bad request")
    }

    if (target.protocol !== "https:" || target.hostname !== "www.qrz.com")
      return sendResponse(res, 400, TEXT_TYPE, "Bad request")

    getqrzimage(target.toString(), res).catch((err: any) => {
      this.logger?.error(`qrz image request failed: ${err}`)
      if (!res.headersSent) sendResponse(res, 502, TEXT_TYPE, "Bad gateway")
      else res.destroy()
    })
  }

  /** Stream a JSON file from the assets folder (basename only: no traversal). */
  private serveJson(urlPath: string, req: any, res: any): void {
    const filename: string = path.basename(urlPath)

    // Chrome DevTools probes for a workspace-mapping file; answer 404 quietly.
    if (filename === "com.chrome.devtools.json")
      return sendResponse(res, 404, TEXT_TYPE, "Not found")

    const filepath = path.join(`${config.__path__}assets`, filename)

    if (req.headers["sec-gpc"] === "1") {
      this.logger?.info(`gpc request detected`)
    }

    let size: number
    try {
      const st = fs.statSync(filepath)
      if (!st.isFile()) return error404(res)
      size = st.size
    } catch (e) {
      this.logger?.info(`json file not found: ${filename}`)
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

    fileStream.on("error", (err) => {
      this.logger?.error(`Error reading the file: ${err}`)
      if (!res.headersSent)
        sendResponse(res, 500, TEXT_TYPE, "Internal Server Error")
      else res.destroy()
    })

    res.on("close", () => fileStream.destroy())
  }

  /** Serve a static asset from the folder mapped to its extension. */
  private serveStatic(urlPath: string, res: any): void {
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
  }

  start(): void {
    try {
      const web = http.createServer(this.requestListener)
      this.server = web

      web.on("error", (err: any) => {
        this.logger?.error(`Web server error: ${err}`)
      })

      web.listen(this.port, this.host, () => {
        this.logger?.info(
          `Web server is running on ${this.host}:${this.port}`,
        )
      })
    } catch (e: any) {
      this.logger?.info(`Error in webserver creation: ${e.toString()}`)
    }
  }

  async close(): Promise<void> {
    if (!this.server) return
    await new Promise<void>((resolve) => {
      this.server!.close(() => resolve())
    })
    this.server = null
  }
}
