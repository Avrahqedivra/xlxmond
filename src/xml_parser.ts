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


import { parseString } from "xml2js"

/** Free-text fields of reflectorlist.xml that are sanitized before parsing. */
const REFLECTOR_TEXT_FIELDS: string[] = [
  "comment",
  "country",
  "name",
  "dashboardurl",
]

// ─────────────────────────────────────────────────────────────────────────────
// XML helpers: sync parsing and sanitizing of loosely-formed XML
// ─────────────────────────────────────────────────────────────────────────────

/**
 * xml2js parses synchronously unless async:true is given; make that explicit and
 * return the result (or throw) so callers never depend on callback ordering
 */
export const parseXmlSync = (xml: string, options: any = {}): any => {
  let error: any = null
  let output: any = null

  parseString(xml, { ...options, async: false }, (err: any, result: any) => {
    error = err
    output = result
  })

  if (error) throw error

  return output
}

export const escapeXml = (text: string): string => {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

/**
 * Makes the text of selected leaf elements (<comment>, <country>, ...) well-formed
 * XML 1.0 so free text such as `DStar <> DMR`, `R&D`, `Café &eacute;` or stray
 * control characters cannot break the parser:
 *
 *  - bare `&`, `<`, `>` are escaped
 *  - the 5 predefined entities and valid numeric references are kept (normalized)
 *  - HTML named entities (&eacute; &nbsp; &euro; ...) are not defined in XML:
 *    they are converted to numeric references; unknown ones are shown literally
 *  - characters illegal in XML 1.0 (control chars, lone surrogates, U+FFFE/FFFF,
 *    invalid numeric references) are removed
 *  - CDATA sections are left alone (only illegal characters are removed)
 *  - accented / non-ASCII characters are valid XML and are kept as is; typical
 *    UTF-8-read-as-Latin-1 damage ("Ã©" -> "é") is repaired
 */
const XML_PREDEFINED_ENTITIES: string[] = ["amp", "lt", "gt", "quot", "apos"]

// HTML 4 Latin-1 entities, code points 160..255 in order
const LATIN1_ENTITY_NAMES: string[] = [
  "nbsp", "iexcl", "cent", "pound", "curren", "yen", "brvbar", "sect", "uml", "copy", "ordf", "laquo", "not", "shy", "reg", "macr",
  "deg", "plusmn", "sup2", "sup3", "acute", "micro", "para", "middot", "cedil", "sup1", "ordm", "raquo", "frac14", "frac12", "frac34", "iquest",
  "Agrave", "Aacute", "Acirc", "Atilde", "Auml", "Aring", "AElig", "Ccedil", "Egrave", "Eacute", "Ecirc", "Euml", "Igrave", "Iacute", "Icirc", "Iuml",
  "ETH", "Ntilde", "Ograve", "Oacute", "Ocirc", "Otilde", "Ouml", "times", "Oslash", "Ugrave", "Uacute", "Ucirc", "Uuml", "Yacute", "THORN", "szlig",
  "agrave", "aacute", "acirc", "atilde", "auml", "aring", "aelig", "ccedil", "egrave", "eacute", "ecirc", "euml", "igrave", "iacute", "icirc", "iuml",
  "eth", "ntilde", "ograve", "oacute", "ocirc", "otilde", "ouml", "divide", "oslash", "ugrave", "uacute", "ucirc", "uuml", "yacute", "thorn", "yuml",
]

const EXTRA_HTML_ENTITIES: [string, number][] = [
  ["OElig", 338], ["oelig", 339], ["Scaron", 352], ["scaron", 353], ["Yuml", 376], ["Zcaron", 381], ["zcaron", 382],
  ["fnof", 402], ["circ", 710], ["tilde", 732], ["ensp", 8194], ["emsp", 8195], ["thinsp", 8201],
  ["ndash", 8211], ["mdash", 8212], ["lsquo", 8216], ["rsquo", 8217], ["sbquo", 8218], ["ldquo", 8220], ["rdquo", 8221], ["bdquo", 8222],
  ["dagger", 8224], ["Dagger", 8225], ["bull", 8226], ["hellip", 8230], ["permil", 8240], ["lsaquo", 8249], ["rsaquo", 8250],
  ["euro", 8364], ["trade", 8482], ["larr", 8592], ["rarr", 8594],
]

const HTML_ENTITIES = new Map<string, number>()
LATIN1_ENTITY_NAMES.forEach((name, index) => HTML_ENTITIES.set(name, 160 + index))
for (const [name, code] of EXTRA_HTML_ENTITIES) HTML_ENTITIES.set(name, code)

/** XML 1.0 `Char` production */
const isXmlChar = (cp: number): boolean => {
  return (
    cp === 0x9 ||
    cp === 0xa ||
    cp === 0xd ||
    (cp >= 0x20 && cp <= 0xd7ff) ||
    (cp >= 0xe000 && cp <= 0xfffd) ||
    (cp >= 0x10000 && cp <= 0x10ffff)
  )
}

/** iterates by code point, so a lone surrogate shows up alone and is dropped */
const stripInvalidXmlChars = (text: string): string => {
  let out = ""

  for (const ch of text) {
    if (isXmlChar(ch.codePointAt(0) as number)) out += ch
  }

  return out
}

/** "Ã©" (UTF-8 bytes read as Latin-1) -> "é"; only when it round-trips cleanly */
const repairMojibake = (text: string): string => {
  if (
    !/[Â-ô][\u0080-¿]/.test(text) ||
    !/^[\u0000-ÿ]*$/.test(text)
  )
    return text

  const repaired = Buffer.from(text, "latin1").toString("utf8")

  return repaired.indexOf("�") === -1 ? repaired : text
}

/** bare `&` -> `&amp;`, HTML entities -> numeric references, invalid refs dropped */
const fixEntities = (text: string): string => {
  return text.replace(
    /&(#x[0-9a-fA-F]+;|#[0-9]+;|[A-Za-z][A-Za-z0-9]*;)?/g,
    (_match: string, ref?: string) => {
      // bare ampersand ("R&D", "A & B", "&foo" without ';')
      if (!ref) return "&amp;"

      const name = ref.slice(0, -1)

      if (name.charAt(0) === "#") {
        const cp =
          name.charAt(1) === "x"
            ? parseInt(name.slice(2), 16)
            : parseInt(name.slice(1), 10)
        return isXmlChar(cp) ? `&#${cp};` : ""
      }

      if (XML_PREDEFINED_ENTITIES.indexOf(name) !== -1) return `&${name};`

      const code = HTML_ENTITIES.get(name)

      // unknown entity: keep it as visible text instead of failing the whole document
      return code !== undefined ? `&#${code};` : `&amp;${name};`
    },
  )
}

/** make a piece of character data safe to embed between XML tags */
const sanitizeXmlText = (text: string, repair: boolean = true): string => {
  let out = stripInvalidXmlChars(text)

  if (repair) out = repairMojibake(out)

  return fixEntities(out).replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

const escapeRegExp = (text: string): string =>
  text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

/** sanitize the text of every `<field>...</field>` (plain tag, no attributes) in `xml` */
const sanitizeXmlFields = (
  xml: string,
  fields: string[],
  repair: boolean = true,
): string => {
  if (fields.length === 0) return xml

  const re = new RegExp(
    `<(${fields.map(escapeRegExp).join("|")})>([\\s\\S]*?)<\\/\\1>`,
    "g",
  )

  return xml.replace(re, (_match: string, tag: string, body: string) => {
    // odd indexes are CDATA sections (captured by the split), even ones plain text
    const clean = body
      .split(/(<!\[CDATA\[[\s\S]*?\]\]>)/)
      .map((part: string, index: number) =>
        index % 2 === 1
          ? stripInvalidXmlChars(part)
          : sanitizeXmlText(part, repair),
      )
      .join("")

    return `<${tag}>${clean}</${tag}>`
  })
}

/** Sanitize the free-text fields of reflectorlist.xml (name kept for API compatibility). */
export const sanitizeComments = (xml: string): string =>
  sanitizeXmlFields(xml, REFLECTOR_TEXT_FIELDS)

/** bytes -> string: UTF-8 (BOM tolerated), falling back to Windows-1252 for legacy files */
export const decodeXmlBuffer = (buffer: Buffer): string => {
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xef &&
    buffer[1] === 0xbb &&
    buffer[2] === 0xbf
  )
    buffer = buffer.subarray(3)

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer)
  } catch (e) {
    try {
      return new TextDecoder("windows-1252").decode(buffer)
    } catch (e2) {
      return buffer.toString("latin1")
    }
  }
}

