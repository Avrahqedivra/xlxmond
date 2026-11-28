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
import { Logger } from "./logger.js"
import * as config from "./config.js"
import * as globals from "./globals.js"
import { FileDownloader } from "./filedownloader.js"
import { scrapeUrl } from "./scrap_modules.js"
import {
  parseXmlSync,
  sanitizeComments,
  decodeXmlBuffer,
  escapeXml,
} from "./xml_parser.js"
import { REFLECTOR_DOWN_AFTER_SECONDS } from "./constants.js"
import { ReflectorDisplayItem } from "./types.js"

export interface DataManagerOptions {
  logger: Logger | null
  onReflectorsUpdated?: (list: any[]) => void
  onDmridUpdated?: (list: any[]) => void
}

export class DataManager {
  private logger: Logger | null
  private reflectorList: any[] = []
  private dmridList: any[] = []
  private dmridMap: Map<string, any> = new Map()
  private reflectorListTime: number = Date.now()
  private onReflectorsUpdated?: (list: any[]) => void
  private onDmridUpdated?: (list: any[]) => void

  constructor(options: DataManagerOptions) {
    this.logger = options.logger
    this.onReflectorsUpdated = options.onReflectorsUpdated
    this.onDmridUpdated = options.onDmridUpdated
  }

  getReflectorList(): any[] {
    return this.reflectorList
  }

  getDmridList(): any[] {
    return this.dmridList
  }

  setReflectorList(list: any[]): void {
    this.reflectorList = Object.freeze(list) as any[]
    if (this.onReflectorsUpdated) this.onReflectorsUpdated(this.reflectorList)
  }

  setDmridList(list: any[]): void {
    this.dmridList = Object.freeze(list) as any[]
    if (this.onDmridUpdated) this.onDmridUpdated(this.dmridList)
  }

  /** Convert the xlxd log file into the dashboard JSON shape and persist it
   *  to `xlxd.json` so a restart can seed the UI before live data arrives. */
  createLogTableJson(): any {
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
      this.logger?.error(`Error parsing ${config.__xlxdlog_file__}: ${err}`)
      return message
    }

    try {
      fs.writeFileSync(
        config.__log_path__ + "xlxd.json",
        JSON.stringify(message, null, 4),
        { encoding: "utf-8", flag: "w" },
      )
    } catch (err: any) {
      this.logger?.error(`Error writing ${config.__log_path__}xlxd.json: ${err}`)
    }

    return message
  }

  /** Look up a DMR user by callsign (O(1) via dmridMap). */
  getRadioIdRecord(callsign: string): any {
    return this.dmridMap.get(callsign) ?? null
  }

  /** Load the subscriber JSON (DMR IDs) and rebuild the lookup map. */
  parseDmrIdList(): void {
    const file = `${config.__path__}assets/${config.__subscriber_file__}`

    if (!fs.existsSync(file)) {
      this.logger?.error(`DMR id file ${file} not found`)
      return
    }

    try {
      const users = JSON.parse(
        fs.readFileSync(file, { encoding: "utf8", flag: "r" }),
      ).users

      this.setDmridList(Array.isArray(users) ? users : [])
      this.logger?.info(`loaded ${this.dmridList.length} DMR ids`)

      this.dmridMap.clear()
      for (const u of this.dmridList)
        if (u?.callsign) this.dmridMap.set(u.callsign, u)
    } catch (err: any) {
      this.logger?.error(`Error parsing ${file}: ${err}`)
    }
  }

  /** Parse `reflectorlist.xml` into the reflector list.
   *  The file is decoded (UTF-8 / Windows-1252) and its free-text fields are
   *  sanitized first; the file mtime is kept to decide "up" vs "down" later. */
  parseXmlReflectorList(): void {
    const file = `${config.__path__}assets/reflectorlist.xml`

    if (!fs.existsSync(file)) return

    this.setReflectorList([])

    try {
      const xmldata: string = sanitizeComments(
        decodeXmlBuffer(fs.readFileSync(file)),
      )
      const results = parseXmlSync(xmldata)
      const list = results?.XLXAPI?.answer?.[0]?.reflectorlist?.[0]?.reflector

      if (Array.isArray(list)) this.setReflectorList(list)

      // "now" for the down/up decision is when the list was produced, not when it is displayed
      this.reflectorListTime = fs.statSync(file).mtimeMs
    } catch (err: any) {
      this.logger?.error(`Error parsing ${file}: ${err}`)
    }
  }

  /** Serialise the reflector list for the dashboard, normalising uptime to
   *  either "down" or "<n>days". */
  getReflectors(): ReflectorDisplayItem[] {
    const js: ReflectorDisplayItem[] = []
    const listTimeSec = this.reflectorListTime / 1000

    for (let item of this.reflectorList) {
      const uptimeSeconds: number = parseInt(item["uptime"], 10)
      let lastContact: number = parseInt(item["lastcontact"], 10)

      // tolerate a millisecond timestamp
      if (lastContact > 1e11) lastContact = lastContact / 1000

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

  getModules(): any {
    return JSON.parse(
      fs.readFileSync(`${config.__path__}assets/modules.json`, {
        encoding: "utf8",
        flag: "r",
      }),
    )
  }

  scrapModules(): void {
    this.logger?.info("\nLoading modules...")

    scrapeUrl(`${config.__xlx_dashboard_url__}/index.php?show=modules`)
      .then((payload) => {
        try {
          fs.writeFileSync(
            `${config.__path__}assets/modules.json`,
            JSON.stringify(payload, null, 4),
            { encoding: "utf-8", flag: "w" },
          )
        } catch (err: any) {
          this.logger?.error(`Error writing modules.json: ${err}`)
        }
      })
      .catch((err) => {
        console.error(err)
      })
  }

  /** Download data files (subscriber IDs, reflector list). Returns Promise<boolean>. */
  downloadData(): Promise<boolean> {
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

    this.logger?.info(
      "\nStarting files download, be patient, it could take several minutes...",
    )

    return downloader
      .downloadAndWriteFiles(envFiles)
      .then(() => {
        this.logger?.info(`\nAll files downloaded and saved. ${globals.__OK__}`)
        this.parseXmlReflectorList()
        return true
      })
      .catch((err: any) => {
        this.logger?.error(`File download failed: ${err}`)
        return false
      })
  }
}
