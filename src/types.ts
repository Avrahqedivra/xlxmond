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

/**
 * Common data interfaces for network traffic, reflectors, and template rendering.
 */

export interface LinkedPeerEntry {
  Callsign: string
  IP: string
  LinkedModule: string
  Protocol: string
  ConnectTime: string
  LastHeardTime: string
}

export interface LinkedNodeEntry {
  Callsign: string
  IP: string
  LinkedModule: string
  Protocol: string
  ConnectTime: string
  LastHeardTime: string
}

export interface HeardUserStationEntry {
  Callsign: string
  Packet: string
  ViaNode: string
  OnModule: string
  ViaPeer: string
  LastHeardTime: string
}

export interface TrafficSnapshot {
  Version: string
  LinkedPeers: {
    Reflector: any[]
    Peer: LinkedPeerEntry[]
  }
  LinkedNodes: {
    Reflector: any[]
    Nodes: LinkedNodeEntry[]
  }
  HeardUsers: {
    Reflector: any[]
    Station: HeardUserStationEntry[]
  }
  onair: string
  offair: string
  talker: any
}

export interface TrafficMessage {
  xlxd: TrafficSnapshot
}

export interface ReflectorDisplayItem {
  name: string
  lastip: string
  dashboardurl: string
  uptime: string
  lastcontact: string
  country: string
  comment: string
}

export interface TemplateContext {
  siteLogoHtml?: string
  buttonBarHtml?: string
  footerHtml?: string
}
