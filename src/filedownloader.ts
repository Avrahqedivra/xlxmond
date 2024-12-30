/*
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
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

import fs from "fs"
import * as https from 'https'
import * as http from 'http'

import { logger } from "./monitor.js"
import * as globals from "./globals.js"

/**
 * Downloads file from remote HTTP[S] host and puts its contents to the
 * specified location.
 */
export class FileDownloader {
  constructor() {
    try {
      // create assets folder if needed
      if (!fs.existsSync('assets'))
        fs.mkdirSync('assets')
    } 
    catch (err) {
    }
  }

  async downloadAndWriteFiles(fileDataArray: {  path: string, file: string, url: string, stale: number }[]): Promise<void[]> {
    const downloadPromises = fileDataArray.map(({ url, path, file, stale }) => {
      let filename: string = path+file
  
      const protocol = !url.charAt(4).localeCompare('s') ? https : http

      return new Promise<void>((resolve, reject) => {
        if (file.length == 0) {
          resolve()
        }

        if (fs.existsSync(filename) && (Date.now() - fs.statSync(filename).mtime.getTime()) / 1000 < stale) {
            logger.info(`${file} is current, not downloaded\n`)
            resolve()
        }
        else {
          const tempfilename = filename + ".tmp"

          // remove any older tmp file
          if (fs.existsSync(tempfilename))
            fs.unlinkSync(tempfilename)

          const file = fs.createWriteStream(tempfilename)

          const request = protocol.get(url, (response) => {
            response.pipe(file)

            file.on('finish', () => {
              file.close()

              // if downloaded file size is zero, delete temp file
              if (fs.statSync(tempfilename).size == 0) {
                fs.unlinkSync(tempfilename)
                logger.info(`${filename} downloaded with size 0 ${globals.__WARNING__}`)
              }
              else {
                // if downloaded file looks ok, delete old .json, rename temp file
                if (fs.existsSync(filename))
                  fs.unlinkSync(filename)
                fs.renameSync(tempfilename, filename)
                logger.info(`${filename} downloaded ${globals.__OK__}`)
              }

              logger.info('File downloaded and saved.\n')  

              resolve()
            })
          })

          request.on('error', (error) => {
            // close if not done
            try { file.close() } catch(e) {}

            // if downloaded screwed up, delete temp file
            if (fs.existsSync(tempfilename))
              fs.unlinkSync(tempfilename)

            logger.info(`downloading the file: ${filename} ${globals.__FAILED__} with ${error}` )
            reject(error)
          })
        }
      })
    })

    return Promise.all(downloadPromises)
  }
}

// https://github.com/andresusanto/easydl
// https://stackoverflow.com/questions/43127835/how-to-wait-for-all-async-tasks-to-finish-in-node-js
