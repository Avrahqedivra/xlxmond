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

import { Crc16 } from './crc16.js'
import * as config from './config.js'
import { abort } from 'process'

export let crc16: Crc16 = new Crc16()

class GenCode {
  private callsign: string = ''
  private options: string = ''

  constructor(argv: string[]) {
    if (argv.length < 1) {
      this.usage()
      throw(abort)
    }

    for (let i=0; i<argv.length; i++) {
      if (argv[i].startsWith('-'))
        this.options = argv[i].trim()
      else
        this.callsign = argv[i].trim()
    }
  
    if (this.options === '-c' || this.options === '-u' )
      this.callsign = this.callsign.toUpperCase()
    
    if (this.options === '-m' || this.options === '-l')
      this.callsign = this.callsign.toLowerCase()

    if (this.callsign === '') {
      this.usage()
      throw(abort)
    }
  }

  usage(): void {
    console.log("\nusage: node ./dist/gencode.js [-c] callsign\n\toptional -c will uppercase the callsign\n\toptional -m will lowercase the callsign\n")
  }

  compute(): [ string, string ] {
    let code = crc16.compute(this.callsign, config.__web_secret_key__).toString()
    return [ this.callsign, code ]
  }
}

try {
  let gencode = new GenCode(process.argv.slice(2))

  let [ callsign, code ] = gencode.compute()
  console.log("\nLogin/Passcode generator for NDMonitor v1.7.0\nCopyright (c) 2023 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>\n")
  console.log(callsign + " passcode is " + code + "\n")
} 
catch(e) {

}
