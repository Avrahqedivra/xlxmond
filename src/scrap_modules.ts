// scrape.js
import * as cheerio from 'cheerio';

export interface ReflectorModeConfig { urcall: string; dtmf: string; }
export interface ReflectorModule {
  module: string;
  name: string;
  users: number;
  dplus: ReflectorModeConfig;
  dextra: ReflectorModeConfig;
  dcs: ReflectorModeConfig;
  dmr: number;
  ysf_dg_id: number;
  m17: string;
}
export interface ReflectorModulesPayload { modules: ReflectorModule[]; }

/**
 * Parse an HTML string, extract table.listingtable, return { modules: [...] }.
 * @param {string} html
 * @returns {{ modules: Array<object> }}
 */
export function scrapeListingTable(html: string) {
  const $ = cheerio.load(html);
  const table = $('table.listingtable');
  if (!table.length) throw new Error('table.listingtable not found');

  const dataRows = table.find('tr').filter((_, tr) => $(tr).find('td').length > 0);

  const modules = dataRows.map((_, tr) => {
    const cells = $(tr).find('td').map((_, td) =>
      $(td).text().replace(/\s+/g, ' ').trim()
    ).get();

    return {
      module:    cells[0],
      name:      cells[1],
      users:     parseInt(cells[2], 10) || 0,
      dplus:  { urcall: cells[3], dtmf: cells[4] },
      dextra: { urcall: cells[5], dtmf: cells[6] },
      dcs:    { urcall: cells[7], dtmf: cells[8] },
      dmr:       parseInt(cells[9], 10) || 0,
      ysf_dg_id: parseInt(cells[10], 10) || 0,
      m17:       cells[11]
    };
  }).get();

  // console.log(`Scraped ${JSON.stringify(modules)} modules from listing table.`);

  return { modules };
}

/**
 * Fetch a URL, scrape its listing table, return { modules: [...] }.
 * @param {string} url
 * @param {RequestInit} [options]  // e.g. { headers: { ... } }
 * @returns {Promise<{ modules: Array<object> }>}
 */
export async function scrapeUrl(url: string, options: RequestInit = {}) {
  const res = await fetch(url, {
    redirect: 'follow',
    ...options,
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; reflector-scraper/1.0)',
      ...(options.headers ?? {})
    }
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
  }

  const html = await res.text();
  return scrapeListingTable(html);
}
