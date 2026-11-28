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
 * Application-wide constants, timeouts, MIME types, and static asset mapping.
 */

export const __version__: string = "3.0.0"

export const SESSION_TTL_MS = 60 * 60 * 1000 // idle HTTP-auth sessions are dropped after 1h
export const SESSION_SWEEP_MS = 60 * 1000
export const BROADCAST_MIN_INTERVAL_MS = 250 // max dashboard push rate (urgent on/off air bypasses it)
export const RECONNECT_DELAY_MS = 5000
export const KEEPALIVE_FIRST_DELAY_MS = 15000
export const KEEPALIVE_INTERVAL_MS = 20000
export const SERVER_SILENCE_TIMEOUT_MS = 120000 // no datagram from xlxd for this long => reconnect
export const REFLECTOR_DOWN_AFTER_SECONDS = 24 * 3600 // reflector considered down if last contact is older than this

export const HTML_TYPE = "text/html; charset=utf-8"
export const TEXT_TYPE = "text/plain; charset=utf-8"

/** Static asset routing table: request extension -> mime type + folder under config.__path__. */
export const filetypes: Record<string, { mimetype: string; folder: string }> = {
  ".ico": { mimetype: "image/x-icon", folder: "/images" },
  ".webp": { mimetype: "image/webp", folder: "/media" },
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
