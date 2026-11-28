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
import * as config from "./config.js"
import { __version__ } from "./constants.js"

/** Page templates are static at runtime: read each file once and reuse. */
export const templateCache = new Map<string, string>()

export const loadTemplate = (filename: string): string => {
  const cached = templateCache.get(filename)
  if (cached !== undefined) return cached
  const data = fs.readFileSync(filename, { encoding: "utf8", flag: "r" })
  templateCache.set(filename, data)
  return data
}

/** Replace every occurrence of `key` with `value` without regex semantics
 *  (so `$&` and friends in the value are not interpreted). */
export const replaceAll = (data: string, key: string, value: any): string => {
  return data.split(key).join(String(value))
}

/** Expand the `__XXX__` placeholders of a page template.
 *  `mobile` selects the mobile/desktop variant (no global state involved). */
export const replaceSystemStrings = (
  data: string,
  mobile: boolean = false,
  siteLogoHtml: string = "",
  buttonBarHtml: string = "",
  footerHtml: string = "",
): string => {
  if (data != null) {
    const replacements: [string, any][] = [
      ["__THEME__", config.__theme__],
      ["__SYSTEM_NAME__", config.__system_name__],
      ["__SITE_LOGO__", siteLogoHtml],
      ["__VERSION__", __version__],
      ["__FOOTER__", footerHtml],
      ["__BUTTON_BAR__", buttonBarHtml],
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
