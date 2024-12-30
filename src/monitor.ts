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
 *  Copyright(c) 2023-25 F4JDN - Jean-Michel Cohen
 *  
*/

import fs from 'fs'
import readline from 'readline'

import { WebSocketServer } from 'ws'
import udp from 'node:dgram'

import http from 'http'
import https from 'https'

import { parseString, Builder } from "xml2js";

import { FileDownloader } from './filedownloader.js'
import { Logger } from './logger.js'
import { Crc16 } from './crc16.js'

import * as config from './config.js'
import * as globals from './globals.js'
import * as sessionmgr from './session.js'

export let __version__: string      = '1.0.0'
export let __siteLogo_html__: any   = ''
export let __buttonBar_html__: any  = ''
export let __footer_html__: any     = ""
export let __mobilePhone__: boolean = false
export let __reflectorList__: any[] = []
export let __dmridList__: any[] = []

export let logger: Logger = null
export let monitor: Monitor = null
export let crc16: Crc16 = null

// system variables
const extensions: string[] = ['.ico', '.jpg', '.png', '.gif', '.css', '.js', '.mp3', '.mp4', '.webm', '.mpeg', '.ogg', '.ppt', '.pptx']

const loadTemplate = (filename: string): string => {
  return fs.readFileSync(filename, { encoding: 'utf8', flag: 'r' })
}

const replaceSystemStrings = (data: string): string => {
  if (data != null) {
    return data.replace('__THEME__',  config.__theme__)
                .replace('__SYSTEM_NAME__',  config.__system_name__)
                .replace('__SITE_LOGO__',  __siteLogo_html__)
                .replace('__VERSION__',  __version__)
                .replace('__FOOTER__',  __footer_html__)
                .replace('__BUTTON_BAR__',  __buttonBar_html__)
                .replace('__SOCKET_SERVER_PORT__',  `${config.__socketServerPort__}`)
                .replace('__START_TOT__',  `${config.__start_tot__}`)
                .replace('__BANNER_DELAY__',  `${config.__bannerDelay__}`)
                .replace('__MOBILE__',  `${__mobilePhone__}`)
                .replace("__MOD_FILTER__", `${config.__mod_filter__}`)
                .replace("__MOD_ORDER__", `${config.__mod_order__}`)
                .replace("__MOD_HILITE__", `${config.__mod_hilite__}`)
                .replace("__MOD_COLORS__", `${config.__mod_colors__}`)
                .replace("__MOD_NUMBER__", `${config.__mod_number__}`)
                .replace("__MOD_NAMES__", `${config.__mod_names__}`)
                .replace("__DYNAMIC_MOD__", `${config.__dynamic_mod__}`)        
  }
  
  return data
}

export class Monitor {
  public  ticker: any       = null
  private client: any       = null
  private reflector: any[]  = []
  private stations: any[]   = []
  private nodes: any[]      = []
  private modules: any[]    = []
  private onair: any        = ''
  private offair: any       = ''
  private jsonStr           = {}
  private dashboardServer: WebSocketServer = null
  private webServer = null

  constructor() {
  }

  createLogTableJson() {
    let xmlfixed: string = ''
    let buffer:string[] = []
    let message: any = {'xlxd': {}}

    if (fs.existsSync(config.__xlxdlog_file__)) {
      buffer = fs.readFileSync(config.__xlxdlog_file__).toString('utf-8').split("\n")

      try {
        if (fs.existsSync(config.__xlxdlog_file__)) {
          let reflector: string = ''

          for(let i=0; i<buffer.length; i++) {
            let line = buffer[i]
            // Each line in input.txt will be successively available here as `line`.
            // console.log(`Line from file: ${line}`);

            try {
              if (line.startsWith("<XLX") && reflector == "")
                reflector = line.substring(1, 7)

              line = line.replace('<STATION>', '<Station>').replace('</STATION>', '</Station>')
              .replace('<NODE>', '<Nodes>').replace('</NODE>', '</Nodes>')
              .replace('<PEER>', '<Peer>').replace('</PEER>', '</Peer>')
              .replace('<Via peer>', '<ViaPeer>').replace('</Via peer>', '</ViaPeer>')
              .replace('<Via node>', '<ViaNode>').replace('</Via node>', '</ViaNode>')
              .replace('<On module>', '<OnModule>').replace('</On module>', '</OnModule>')
              .replace('<'+reflector+'  heard users>', '<HeardUsers><Reflector>'+reflector+'</Reflector>').replace('</'+reflector+'  heard users>', '</HeardUsers>')
              .replace('<'+reflector+'  linked peers>', '<LinkedPeers><Reflector>'+reflector+'</Reflector>').replace('</'+reflector+'  linked peers>', '</LinkedPeers>')
              .replace('<'+reflector+'  linked nodes>', '<LinkedNodes><Reflector>'+reflector+'</Reflector>').replace('</'+reflector+'  linked nodes>', '</LinkedNodes>')


              if ((line.indexOf('</') == -1) || line.startsWith('</')) {
                xmlfixed += line
                if (line.toLowerCase().startsWith('<?xml'))
                  xmlfixed = xmlfixed + '<xlxd>'
              }
              else {
                parseString(line, (err, results) => {
                  let key = Object.keys(results)[0]
                  xmlfixed += `<${key}>${ results[key]}</${key}>`
                })
              }
            }
            catch(err) {
              xmlfixed += line
            }
          }

          xmlfixed += "</xlxd>"

          parseString(xmlfixed, { explicitArray: false }, (error, result) => {
            message = result
          })
        }

        fs.writeFileSync(config.__log_path__ + 'xlxd.json', JSON.stringify(message, null, 4), {encoding:'utf-8',flag:'w'})
      }
      catch (err) {
      }
    }

    return message
  }

  getRadioIdRecord(callsign: string) {
    for(let i=0; i<__dmridList__.length; i++) {
      if (__dmridList__[i].callsign == callsign)
        return __dmridList__[i]
    }

    return null
  }

  parseDmrIdList() {
    if (fs.existsSync(`${config.__path__}assets/${config.__reflectors_file__}`)) {
      __dmridList__ = JSON.parse(fs.readFileSync(`${config.__path__}assets/${config.__reflectors_file__}`, { encoding: 'utf8', flag: 'r' })).users
      console.log('done')
    }
  }

  parseXmlReflectorList() {
    if (fs.existsSync(`${config.__path__}assets/reflectorlist.xml`)) {
      let xmldata: any = fs.readFileSync(`${config.__path__}assets/reflectorlist.xml`)
      
      __reflectorList__ = []

      parseString(xmldata, (err, results) => {
        if (results["XLXAPI"] && results["XLXAPI"]['answer'][0] && results["XLXAPI"]['answer'][0]['reflectorlist'][0] && results["XLXAPI"]['answer'][0]['reflectorlist'][0]['reflector'])
          __reflectorList__ = results["XLXAPI"]['answer'][0]['reflectorlist'][0]['reflector']
      })
    }
  }

  getReflectors() {
    let js: any = []

    for(let item of __reflectorList__) {
      let uptime: number = parseInt(item["uptime"]) / (3600*24)

      js.push({
          "name": item["name"],
          "lastip": item["lastip"],
          "dashboardurl": item["dashboardurl"],
          "uptime": (parseInt(item["lastcontact"]) / (3600*24*1000) > uptime) ? "down": uptime + 'days',
          "lastcontact":  item["lastcontact"],
          "country": item["country"],
          "comment":  item["comment"]
      })
    }

    return js
  }

  /**
   * 
   * to be done https://objsal.medium.com/how-to-encode-node-js-response-from-scratch-ce520018d6
   * 
   */

  requestListener(req: any, res: any) {
    try {
      var isIpad = !!req.headers['user-agent'].match(/iPad/);
      var isAndroid = !!req.headers['user-agent'].match(/Android/);

      if (__mobilePhone__ = (isIpad || isAndroid))
        logger.info(`mobile phone connection ${req.headers['user-agent']}`)
    }
    catch(e) {
      __mobilePhone__ = false
    }

    if (config.__web_auth__) {
      let authHeader = req.headers['authorization']

      if (!authHeader) {
        res.setHeader('WWW-Authenticate', 'Basic realm="ndmonitor"')
        res.writeHead(401, 'Content-Type', 'text/plain')
        res.end()
        return
      }

      if (authHeader.split(' ')[0] == 'Basic') {
        let decodedData = Buffer.from(authHeader.split(' ')[1], 'base64').toString()
        let [username, password] = decodedData.split(':')

        if (crc16.compute(username, config.__web_secret_key__).toString() != password) {
          res.setHeader('WWW-Authenticate', 'Basic realm="ndmonitor"')
          res.writeHead(401, 'Content-Type', 'text/html')
          res.end()
          return
        }
        
        /**
         * authenticated, add to session and continue
         */
        let requestip = req.socket.remoteAddress.startsWith('::1') ? '127.0.0.1' : req.socket.remoteAddress.replace(/^.*:/, '')
        if (!sessionmgr.sessions.hasOwnProperty(requestip)) {
          // logger.info(`adding ipaddress to session ${requestip}`)
          sessionmgr.sessions[requestip] = new sessionmgr.Session(requestip, 0)
        }
      }
    }

    const acceptedEncodings = req.headers['accept-encoding'] || ''

    let index = req.url.toString().indexOf('https://www.qrz.com/lookup/')
    if (index != -1) {
      const getqrzimage = async (protocol: any, url: string, res:any): Promise<void> => {
        return new Promise<void>((resolve, reject) => {
          const request = protocol.get(url, (response: any) => {
            response.pipe(res)
          })
        })
      }

      const url = req.url.toString().substring(index)
      const protocol = !url.charAt(4).localeCompare('s') ? https : http
      getqrzimage(protocol, url, res)
      return
    }

    if (req.url.toString().endsWith('.json')) {
      let fileurl:string = req.url.toString()
      let filename: string = fileurl.substring(fileurl.lastIndexOf('/') + 1, fileurl.length)

      let filepath = `${config.__path__}assets/${filename}`

      try {
        const gpcValue = req.header('Sec-GPC')
  
        if (gpcValue === "1") {
          // signal detected, do something
          logger.info(`gpc request detected`)
        }
      }
      catch(e) {
      }
  
      if (!fs.existsSync(filepath)) {
        logger.error(`Error file ${filepath} doesn't exists`);
        res.statusCode = 500;
        res.end(`The requested file ${filename} doesn't exists`);
        return
      }

      res.setHeader('Content-Type', 'application/json')
      res.setHeader('Content-Length', fs.statSync(filepath).size);

      const fileStream = fs.createReadStream(filepath)

      // Send the JSON file in chunks
      let isFirstChunk = true
      fileStream.on('data', (chunk) => {
        // Send the chunk to the response
        res.write(chunk);
      })

      fileStream.on('end', () => {
        res.end()
      })

      // Handle any errors that might occur during streaming
      fileStream.on('error', (err) => {
        logger.error(`Error reading the file: ${err}`);
        res.statusCode = 500;
        res.end('Internal Server Error');
      })

      return
    }

    let error404 = (res: any) => {
      fs.promises.readFile(`${config.__path__}pages/error404.html`)
      .then(content => {
        res.writeHead(404, 'Content-Type', 'text/html')
        res.end(content)
      })
    }

    switch (req.url) {
      case '/':
      case '/index.html':
        res.writeHead(200, "Content-Type", "text/html")
        res.end(replaceSystemStrings(loadTemplate(`${config.__path__}pages/index_template.html`)))
        break

      case '/reflectors.html':
        res.writeHead(200, "Content-Type", "text/html")
        res.end(replaceSystemStrings(loadTemplate(`${config.__path__}pages${req.url}`)))
        break;

      default:
        var dotOffset = req.url.lastIndexOf('.');
        if (dotOffset == -1 || !extensions.includes(req.url.substr(dotOffset))) {
          return error404(res)
        }

        var filetype = {
            '.html' : { mimetype: 'text/html', folder: '/pages'},
            '.htm' : { mimetype: 'text/html', folder: '/pages'},
            '.ico' : { mimetype: 'image/x-icon', folder: '/images'},
            '.jpg' : { mimetype: 'image/jpeg', folder: '/images'},
            '.png' : { mimetype: 'image/png', folder: '/images'},
            '.gif' : { mimetype: 'image/gif', folder: '/images'},
            '.css' : { mimetype: 'text/css', folder: '/css' },
            '.mp3' : { mimetype: 'audio/mp3', folder: '/media' },
            '.mp4' : { mimetype: 'video/mp4', folder: '/media' },
            '.mpeg' : { mimetype: 'video/mpeg', folder: '/media' }, 
            '.ogg' : { mimetype: 'video/ogg', folder: '/media' },
            '.webm' : { mimetype: 'video/webm', folder: '/media' },
            '.ppt' : { mimetype: 'application/vnd.ms-powerpoint', folder: '/media' },
            '.pptx' : { mimetype: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', folder: '/media' },
            '.js' :  { mimetype: 'text/javascript', folder: '/scripts' }
          } [ req.url.substr(dotOffset) ];
  
        let folder: string = filetype.folder;
        let mimetype: string = filetype.mimetype;
        let filename: string = req.url.toString()
  
        // any icon from old apple device
        if (filename.indexOf('apple-touch-icon') != -1)
          filename = "/apple-touch-icon.png"

        // if bitmap does not exist return site logo
        if (!fs.existsSync(`${config.__path__}${folder}${filename}`)) {
          if (folder === '/images')
            filename = '/sitelogo.png'
          else {
            res.writeHead(200, mimetype)
            res.end("")
            return
          }
        }

        try {
          fs.promises.readFile(`${config.__path__}${folder}${filename}`)
            .then(content => {
              res.writeHead(200, mimetype)
              res.end(content)
            }),
            (reason: any) => {
              return error404(res)
            }
        }
        catch(e) {
          return error404(res)
        }
      break
    }
  }

  send(data: Buffer) {
    //sending msg
    this.client.send(data, config.xlx_server_port, config.xlx_server_host, (error: any) => {
      if (error) {
        this.client.close()
      }
    })
  }

  connectToServer() {
    let callsign: string  = ''
    let OnModule: string  = ' '
    let entry: any        = null

    this.client = udp.createSocket('udp4')    // creating a client socket

    this.client.on('message', (buffer: any, info: any) => {
      // console.log('Data received from server : ' + buffer.toString())
      // console.log('Received %d bytes from %s:%d\n', buffer.length, info.address, info.port)

      let msg = JSON.parse(buffer)

      // console.log(JSON.stringify(msg))

      this.onair = ""
      this.offair = ""

      if (msg.hasOwnProperty('PING')) {
        this.send(Buffer.from('PONG'))
        console.log("got PING message")
      }

      if (msg.hasOwnProperty('reflector')) {
        this.reflector = msg.reflector
        console.log(this.reflector.toString() + " reflector")
      }

      if (msg.hasOwnProperty('modules')) {
        this.modules = msg.modules
        console.log(this.modules.toString() + " modules")
      }

      if (msg.hasOwnProperty('nodes')) {
        this.nodes = msg.nodes
        // console.log(this.nodes.toString() + " nodes")
      }

      if (msg.hasOwnProperty('stations')) {
        this.stations = msg.stations
        // console.log(this.stations.toString() + " stations")
      }

      if (msg.hasOwnProperty('onair')) {
        this.onair = msg.onair
        // let omRecord = this.getRadioIdRecord(this.onair)
        console.log(this.onair.toString() + " on Air")
      }

      if (msg.hasOwnProperty('offair')) {
        this.offair = msg.offair
        console.log(this.offair.toString() + " off Air")
      }

      this.jsonStr = {
        'xlxd': {
            'Version':        __version__,
            'LinkedPeers': {
                'Reflector':  this.reflector,
                'Peer':       []
            },
            'LinkedNodes': {
                'Reflector':  this.reflector,
                'Nodes':      []
            },
            'HeardUsers': {
                'Reflector':  this.reflector,
                'Station':    []
            },
            'onair':          this.onair,
            'offair':         this.offair
        }
      }

      /**
       * NODES
       */
      for (let item of this.nodes) {
        callsign = item['callsign'].trim()

        entry = { 
          'Callsign':       `${callsign}   ${item['module']}`,
          'IP':             '*.*.*.*',
          'LinkedModule':   item['linkedto'].trim(),
          'Protocol':       ' ',
          'ConnectTime':    item['time'].trim(),
          'LastHeardTime':  item['time'].trim()
        }

        if (item['module'] === ' ') {
          entry['Protocol'] = callsign.substring(0, 3)
          
          let peers = this.jsonStr['xlxd']['LinkedPeers']['Peer']

          for (let peer of peers) {
            if (callsign == peer['Callsign']) {
                peer['LinkedModule'] = peer['LinkedModule'] + entry['LinkedModule']
                break
            }

            peers.push(entry)
          }
        }
        else
            this.jsonStr['xlxd']['LinkedNodes']['Nodes'].push(entry)
      }

      for (let item of this.stations) {
        callsign = item['callsign'].trim()
        OnModule = ' '

        for (let node of this.nodes) {
          if (item['node'] == node['callsign'] && item['module'] == node['module']) {
            OnModule = node['linkedto']
            break
          }
        }

        // { 'DATE': REPORT_DATE, 'TIME': REPORT_TIME, 'TYPE': REPORT_TYPE.substring(6), 'PACKET': REPORT_PACKET, 'SYS': REPORT_SYS, 'SRC_ID': REPORT_SRC_ID, 'TS': REPORT_TS, 'TGID': REPORT_TGID, 'ALIAS': REPORT_ALIAS, 'DMRID': REPORT_DMRID, 'CALLSIGN': REPORT_CALLSIGN, 'NAME': REPORT_FNAME, 'DELAY': 0 }

        entry = { 
            'Callsign':       callsign.trim(),
            'Packet':         (callsign.trim() == this.onair) ? 'START': (callsign.trim() == this.offair) ? 'END' : 'N/A',
            'ViaNode':        `${item['node'].trim()} ${item['module'].trim()}`,
            'OnModule':       OnModule,
            'ViaPeer':        '',
            'LastHeardTime':  item['time'].trim(),
        }

        this.jsonStr['xlxd']['HeardUsers']['Station'].push(entry)
      }

      this.dashboardServer.clients.forEach((ws: any) => {
        if (ws.fromPage) {
          if (ws.page === 'dashboard')
            ws.send(JSON.stringify({ "TRAFFIC": this.jsonStr["xlxd"] , 'BIGEARS': this.dashboardServer.clients.size }))
        }
      })
    })
  
    setTimeout(() => {
      logger.info('sending initial hello')
      this.send(Buffer.from('hello'))
    }, 500)

    setTimeout(() => {
      logger.info('initializing keep alive')

      this.ticker = setInterval(() => {
        this.send(Buffer.from('ping'))
      }, 20000)
    }, 15000)
  }

  init() {
    /** 
     * https://manytools.org/hacker-tools/ascii-banner/ (rowan cap font)
     */ 
    logger.info(`${globals.__CLEAR__}${globals.__HOME__}`)

    logger.info(`${globals.__BLUE__}    dMP dMP dMP     ${globals.__WHITE__}dMP dMP dMMMMMMMMb  .aMMMb  ${globals.__RED__}dMMMMb  dMMMMb `)
    logger.info(`${globals.__BLUE__}   dMK.dMP dMP     ${globals.__WHITE__}dMK.dMP dMP"dMP"dMP dMP"dMP ${globals.__RED__}dMP dMP dMP VMP `)
    logger.info(`${globals.__BLUE__}  .dMMMK" dMP     ${globals.__WHITE__}.dMMMK" dMP dMP dMP dMP dMP ${globals.__RED__}dMP dMP dMP dMP  `)
    logger.info(`${globals.__BLUE__} dMP"AMF dMP     ${globals.__WHITE__}dMP"AMF dMP dMP dMP dMP.aMP ${globals.__RED__}dMP dMP dMP.aMP   `)
    logger.info(`${globals.__BLUE__}dMP dMP dMMMMMP ${globals.__WHITE__}dMP dMP dMP dMP dMP  VMMMP" ${globals.__RED__}dMP dMP dMMMMP"    `)
                                                               
    logger.info(`${globals.__RESET__}`)
    
    logger.info(`\nNDMonitor v${__version__} (c) 2023-25 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>`)

    // must be first
    __footer_html__ = replaceSystemStrings(loadTemplate(`${config.__path__}pages/${config.__footer__}`))        

    __siteLogo_html__ = replaceSystemStrings(loadTemplate(`${config.__path__}pages/${config.__siteLogo__}`))
    __buttonBar_html__ = replaceSystemStrings(loadTemplate(`${config.__path__}pages/${config.__buttonBar__}`))

    /**
     * dashboard websocket server
     * 
     * create socket server https://github.com/websockets/ws#simple-server
     */
    try {
      logger.info(`creating dashboard socket server on port:${config.__socketServerPort__}`)
      
      this.dashboardServer = new WebSocketServer({ 
        port: config.__socketServerPort__,
        perMessageDeflate: {
          zlibDeflateOptions: {
            // See zlib defaults.
            chunkSize: 1024,
            memLevel: 7,
            level: 3
          },
          zlibInflateOptions: {
            chunkSize: 10 * 1024
          },
          // Other options settable:
          clientNoContextTakeover: true, // Defaults to negotiated value.
          serverNoContextTakeover: true, // Defaults to negotiated value.
          serverMaxWindowBits: 10, // Defaults to negotiated value.
          // Below options specified as default values.
          concurrencyLimit: 10, // Limits zlib concurrency for perf.
          threshold: 1024 // Size (in bytes) below which messages
          // should not be compressed if context takeover is disabled.
        }
        })

      logger.info(`dashboard socket server created ${config.__socketServerPort__} ${globals.__OK__}\n`)

      this.dashboardServer.on('connection', (ws: any, req: any) => {
        let _message: any = {}

        this.jsonStr = this.createLogTableJson()

        /**
        * get connection information (page name)
        * page name
        * 
        * save that into extra properties
        * page
        * fromPage (assume true)
        * connectTime
        */
        const urlParams = new URLSearchParams(req.url.substring(1));
        ws.page = urlParams.get('page') ? urlParams.get('page') : 'generic'
        ws.fromPage = true
        ws.connectTime = Date.now()

        // get ip address
        let requestip = req.socket.remoteAddress.startsWith('::1') ? '127.0.0.1' : req.socket.remoteAddress.replace(/^.*:/, '')

        logger.info(`\nWebSocket connection from page ${ws.page}`)
  
        // prepare initial packet
        if (ws.fromPage) {
          _message['BIGEARS'] = this.dashboardServer.clients.size.toString()
        }

        if (ws.page === 'dashboard')
          _message['PACKETS'] = { 'TRAFFIC': this.jsonStr["xlxd"]  }

        if (ws.page === 'reflectors')
          _message['REFLECTORS'] = this.getReflectors()

        ws.on('error', console.error)
  
        ws.on('message', (payload: any) => {
          // update time
          ws.connectTime = Date.now()

          if (config.__loginfo__)
            logger.info(`command received: ${payload}`)

          let _command = JSON.parse(payload)
        })

        ws.on('close', () => {
          let requestip = req.socket.remoteAddress.startsWith('::1') ? '127.0.0.1' : req.socket.remoteAddress.replace(/^.*:/, '')
          if (config.__web_auth__ && sessionmgr.sessions.hasOwnProperty(requestip))
            delete sessionmgr.sessions[requestip]
        })
  
        ws.send(JSON.stringify({ 'CONFIG': _message }))
      })

      try {
        let hostServer: string = config.__localhost__
        this.webServer = http.createServer(this.requestListener)
        this.webServer.listen(config.__monitor_webserver_port__, hostServer, () => {
          logger.info(`Web server is running on ${hostServer}:${config.__monitor_webserver_port__}`)
        })
      }
      catch(e) {
        logger.info(`Error in webserver creation: ${e.toString()}`) 
      }

    }
    catch(e) {
      logger.info(`Error creating WebSocketServer: ${e.toString()}`)
    }

    /**
     * Download files
    */
    const downloader = new FileDownloader()

    const envFiles: any[] = [  
      { path:  `${config.__path__}assets/`, file:  config.__subscriber_file__, url:  config.__subscriber_url__, stale:  config.__file_reload__ * 24 * 3600 },
      { path:  `${config.__path__}assets/`, file:  config.__reflectors_file__, url:  config.__reflectors_url__, stale:  5 * 24 * 3600 } 
    ]

    logger.info('\nStarting files download, be patient, it could take several minutes...')

    downloader.downloadAndWriteFiles(envFiles).then(() => {
      logger.info(`\nAll files downloaded and saved. ${globals.__OK__}`)

      this.parseXmlReflectorList()
      // this.parseDmrIdList()

      this.connectToServer()
      return true
    }).catch(err => {
      return false
    })
  }
}

logger = new Logger()
crc16 = new Crc16()

if (monitor = new Monitor())
  monitor.init()
