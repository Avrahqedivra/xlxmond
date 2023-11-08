cookieSettingsName = window.location.hostname+"_xlxmond_settings"
settingsValidity = 5	    // 5 days
settings = [ { config: { "theme": "theme-dark", hidetg: false, "last": 0 } }, { "map": { "zoom" : 6.5 } }, { name: "openbridges", "open": true }, {"name": "masters", "open": true }, { "name": "peers", "open": true }];

// localStorage.setItem('theme', themeName)
// localStorage.getItem('theme', themeName)

var zoomValue = 1

var names = []    

names["Andre"] = "André"
names["Francois"] = "François"
names["Herve"] = "Hervé"
names["Jerome"] = "Jérôme"
names["Jerôme"] = "Jérôme"
names["Stephane"] = "Stéphane"
names["Irenee"] = "Irénée"
names["Regis"] = "Régis"
names["Gerard"] = "Gérard"
names["Jean-Noel"] = "Jean-Noël"
names["Remi"] = "Rémi"
names["Clement"] = "Clément"
names["Frederic"] = "Frédéric"
names["Jeremy"] = "Jérémy"
names["Jean-Francois"] = "Jean-François"
names["Gregory"] = "Grégory"    
names["Anne-Cecile"] = "Anne-Cécile"
names["Mickael"] = "Mickaël"
names["Theophile"] = "Théophile"
names["Sebastien"] = "Sébastien"
names["Sbastien"] = "Sébastien"
names["Raphael"] = "Raphaël"
names["Cedric"] = "Cédric"
names["Rene"] = "René"
names["Nathanael"] = "Nathanaël"
names["Joel"] = "Joël"
names["Jeremie"] = "Jérémie"
names["Jerã´me"] = "Jérôme"

function adjustMenuLayoutStyle(f) {
  siteHeader.style.transform = "scale(" + zoomValue + ")"
  siteHeader.style.marginTop = isFixed ?  "3.3rem":"0"
  menubar.style.position = isFixed ? "fixed":"relative"
  lockbutton.classList.remove(isFixed ? "fa-lock-open":"fa-lock")
  lockbutton.classList.add(isFixed ? "fa-lock":"fa-lock-open")
}

function initMenubar() {
    lockbutton = document.getElementById("lockButton")
    menubar = document.getElementById("menubar")
    siteHeader = document.getElementById("siteHeader")
    isFixed = true

    lockbutton.addEventListener("click", () => {
        isFixed = !isFixed
    
        adjustMenuLayoutStyle(isFixed)
    })
    
    adjustMenuLayoutStyle(isFixed)
}

String.prototype.capitalize = function (lower) {
    return (lower ? this.toLowerCase() : this).replace(/(?:^|\s|['`‘’.-])[^\x00-\x60^\x7B-\xDF](?!(\s|$))/g, function (a) {
        return a.toUpperCase()
    })
}

function zoom(v) {
	switch(v) {
		case -1: zoomValue -= 0.10; break
		case  1: zoomValue += 0.10; break
		default: zoomValue = 1; break
	}

	document.getElementById("siteHeader").style["transform"] = "scale(" + zoomValue + ")"
	document.getElementById("siteHeader").style["transform-origin"] = "top center"
}

function enhanceNames(name) {
    if (name != null) {
        name = name.replace(/None/g, "")

        if (names != null && names[name] != null)
            return names[name].capitalize(true)
    }

    return name.capitalize(true)
}

function createCookie(name, value, days) {
    var expires

    if (days) {
        var date = new Date()
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000))
        expires = "; expires=" + date.toGMTString()
    } else {
        expires = ""
    }
    
    // document.cookie = encodeURIComponent(name) + "=" + encodeURIComponent(value) + expires + "; path=/"
    document.cookie = name + "=" + value + expires + "; path=/"
}

function readCookie(name) {
    var nameEQ = name + "="
    var ca = document.cookie.split(';')
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i]
        while (c.charAt(0) === ' ')
            c = c.substring(1, c.length)
        if (c.indexOf(nameEQ) === 0)
            return c.substring(nameEQ.length, c.length)
    }
    return null
}

function saveSettings() {
    themeSettings = document.documentElement.className

    settings = [
        { "config": { "theme": themeSettings, "last": Date.now() } },
        { "map": { "zoom" : (map != null) ? map.getZoom() : 6.5 } }
    ]

    createCookie(cookieSettingsName, JSON.stringify(settings), settingsValidity)

    // alert("Sauvegarde effectuée");
}

function eraseCookie(name) {
    createCookie(name, "", -1)
}    

function adjustTheme() {
    if (themeSettings == "auto") {
        var hr = new Date().getHours()
        // choose dark netween 10PM and 7AM
        if (hr > 22 && hr < 7) {
            if (document.documentElement.className != "theme-dark")
                document.documentElement.className = "theme-dark"
        }
        else {
            if (document.documentElement.className != "theme-light")
                document.documentElement.className = "theme-light"
        }
    }
}

function applyConfig() {
    for(let i=0; i < settings.length; i++) {
        var tbs = settings[i]

        if (tbs.config) {
            themeSettings = tbs.config.theme
			    	$("#insertPoint").show()
    
            if (themeSettings == "auto")
							adjustTheme()
            else
							document.documentElement.className = themeSettings
        }
        else 
					if (tbs.map)
            currentZoom = tbs.map.zoom
    }
}

function getConfigFromLocalStorage() {
    map = null
    themeSettings = "theme-dark"

    // retrieve settings
    if ((cookie = JSON.parse(readCookie(cookieSettingsName))) == null) {
        cookie = settings
        createCookie(cookieSettingsName, JSON.stringify(settings), settingsValidity)
    }
    else {
        if (cookie[0].config.last == null)
            cookie[0].config.last = 0

        settings = cookie
    }
}

const flag64 = []
flag64["at"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUAgMAAADnxWVXAAAACVBMVEXtKTnzcHv///9FjJx3AAAAGklEQVQI12NgIAuEQkAAwyoIWEAaA66dLAAA/KEk6+/EHQQAAAAASUVORK5CYII="
flag64["be"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABcAAAAUBAMAAACUkLs9AAAAElBMVEXtKTkAAAD64ELyZTtUTBZVTRYE41wOAAAAG0lEQVQY02MQFBQUVVJSUmYAASBHZMRw4N4GAFi9EENfoBrcAAAAAElFTkSuQmCC"
flag64["bo"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB0AAAAUBAMAAACDsiv0AAAAD1BMVEXVKx4AeTT54wBTnSPhZhQzAYZEAAAAIUlEQVQY02NgoDFwQQEODEooQIHqfGMUYMAgiAIEqM0HACBCGM/oCyk+AAAAAElFTkSuQmCC"
flag64["ca"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAAUCAMAAADImI+JAAAAM1BMVEX/AAD/MDD/EBD/19f/QED/ICD/r6//////wMD/8PD/oKD/YGD/gID/b2//cHD/UFD/kJAQFQNAAAAAgUlEQVQoz62S2woDIQxEj5doou7l/7+2DwXbwupa2nkIjBwyGAa68oW40vdgKUugmUi2BVAOOGQBjADxFtS8A+xZZ6DW5s8CUJpvVYegAcQ+bBzt3r0bR6fPhzTemPzL+jT7dejhLszPY/I0Yjd3NOJW6xaxhVKoLrbn/2AIvzT8AWsMCOs6h1CtAAAAAElFTkSuQmCC"
flag64["ch"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAANCAIAAAArLKlOAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAFHSURBVChTlVIxTgQxDPTYyR7wlOv5PAW6hpIWCR7CQjaxGWf3CqSjYKSN4sQzHjuL11rl/8ALrEABfs6VWEQNQRiUGe4OU4bcmJkKug9cVE8wXmtosWTWYLqfW5u68nF3z3VXJOHLO0Md4byfhxFSKZlJkYQD3lm8975ubY0AzMLSXsQYEoIhnunph+EVlGndVbWaLSKFtgx41rRbFRpi8MctPdzE27KQ3F02hFIsIKxGmgbl/gR9fdMYgvaUw0K4ze5CjjHcBOvkfMlkh5dS2VKyRU7zCR5i43ruYybLOzsRWaXQIe3lEZxeObsM+HqO1Fuhn8LMA10LOSQ0ymcpH2O+I7VJJT0d8NXl1yTp25XTmn9AqOQcgScBq9tsr+r+7nu+mOWk1GMoNdNNeDrKU2fEOldT3PPiui8NvRf+AyXjSFFWdPcfPqrVgMZwDRUAAAAASUVORK5CYII="
flag64["cl"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUBAMAAABohZD3AAAAFVBMVEUAOabVKx7///9Lc8AQRauQqNjf5vTwpxheAAAAKklEQVQY02NgAAElOGAgzDdG5bumhaDwWZQcUPjMxgakmY/KF0QFg40PAFkJGT1/YYOJAAAAAElFTkSuQmCC"
flag64["co"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUAgMAAADnxWVXAAAACVBMVEUAOJPOESb80RYoeTcGAAAAF0lEQVQI12NYBQELGKjOIAmEQkAAMQwA+9NB7HYGMdMAAAAASUVORK5CYII="
flag64["de"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACEAAAAUBAMAAADxfUlCAAAAD1BMVEXdAAAAAAD/zgD0igBKAABdJSNsAAAAIUlEQVQY02MQRAMCDLQTcUEDDgz0BMZowIBBCQ0o0E4EAL4AHCF2rs9hAAAAAElFTkSuQmCC"
flag64["ec"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUCAMAAACtdX32AAAAnFBMVEX/3QBjXW2NoG8cXab52g9VfHBbgGsDTqLtHCQRVp1zWSBATXqEajvZwDK9uDSIb0bzzAamlB+MjkwSco+xmj/TzQ2HhWJoqpjQshTjwwguZ4jv0w1yWjJ5jFU0aoSchTe6mgnXthCFeUNPa3Hszwq1tDeEuCHNthSBfoFMZnSAdn6OtHh6hYbI19qtxcyrualnm5ywxxONo490umigh32sAAAAd0lEQVQoz2NgGBJAUoZfRJ6HSwKHNIuKIA+XgjQLLml1USE+UUVc0ryGTOLiTGq8OKQFRPR19YwEBZDF2BGAjVHbwJiJkRVJCEVaU0dYWEMZl7ScqpaYGCOfFA5pZjYhfiVZVmYc0uycnNzcnJzIIgwceMFASgMADGkODcjCRY0AAAAASUVORK5CYII="
flag64["es"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUCAMAAACtdX32AAAAVFBMVEX/xACzTwzTsbr8wgDUiSvFawfvwy/GCx7uwBrdmDK/rDnztgDZkjPblALJcSSyZgexOhHNsCfNsCjHjmXnvjC9j068d1F4RUKYUB18TVWvSxy6kqEyHguVAAAAVklEQVQoz83RSRLAIAhEUVQgzpp5uv89cwKsuEr+9lU1C2BoBl/y26xtqSNyIoaQiJIx4nKtWov7mMtx64zS5Xjt5+aiwLyoohSzwJPHdUY/Qmf/fegDe6kKdhTlmsEAAAAASUVORK5CYII="
flag64["fk"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAAUCAMAAADImI+JAAAA8FBMVEUBIWlgdKHUeY4jdLnYVmvyxs1nbprIEC7AyNoOLHElQH0gPHv6+Pm/x9kTfMfg5O1icJ7f4+xklr////8CWmX88fP21dqlbVO3jnmytsDZ3OfOu7aDsdUfdbuBj5y6vb8cOXmwg24zTISwlooJKG6+zdja2tqftsiigXRroc+81epXgLAggcmanYH13uN2bYIxfL2PaGCRlqwwfL2hYD+VvNgwh8Wpvs5godBvUkWNn7tHV4ijj4tOaZtSlcSLm7Tu7u7O0tUAYY8faXCMrsfAmYNzg5Osp5mysX3JiGJooMevm2aorYO1gWPJw6hikagBkklFAAAA+0lEQVQoz8XQ126DMBSA4UOAGFOTKFA2guyddO+9m3S9/9vUJ8ZSLyJ82f8COJxPQhgMs6UBzyLEwnu9ZpiwLVwgFRCnpgZQQRFWMstxnGQZ+B4hLPBZwkdHbNo7m9olJFvaLOjRyXmDt09V0B0MR6OzU72EFi9hfsAI8fxgmeAsoO4O2T3LJATQWqZRq+PPaE18Kl9TvfFQxMWthILJ4/lDqf74tMuTUC7kgSMVMPPG6ffCyyhU15/M3z8Wn/NJXwFhNvh5e86LmcrBzfrl1Y3yK5Wz02v3a5XHoa2AcRrdTaeXneMDBTzs9HrjizCM9pTfpna3yy/w3/0CuwMWbh/ZsdkAAAAASUVORK5CYII="
flag64["fr"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUAgMAAADnxWVXAAAACVBMVEUAI5XtKTn///+i/AH+AAAAFElEQVQI12NgYOBatSo0NIBh6DAATSAu4Xxi9HsAAAAASUVORK5CYII="
flag64["frs"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAQCAMAAAAhxq8pAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAA8UExURf8AAP8HB/9aWv8GBv8ICP8hIf8YGP8yMv84OP9BQf9CQv8fH/8MDP9lZf8pKf8iIv9FRf8CAv8BAQAAAMJjVhgAAAAUdFJOU/////////////////////////8AT0/nEQAAAAlwSFlzAAAK8AAACvABQqw0mAAAAGFJREFUKFNtjkkSwCAIBMm+r/P/v4ZBSksjIg2NBwWVUEnfKIQZiJZd52seI6fe5BCl5ehdJqe/lHmpSKwKpf+gkHzGOcrQedWy7XGdpMjhXZLAaSjkZbhzqfcBXgo3RQAfnmEQfMJBNFUAAAAASUVORK5CYII="
flag64["gb"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAAUCAMAAADImI+JAAAAPFBMVEX////xw8p8jbLnv8pBWY8OLHHw8vfIEC4BIWnWTGKAkLRAWI5LYZXgeIn10tigrMfheYrx2+Htz9hKYJTy9LpmAAAAqUlEQVQoz8XTQRaDIAwFwC8SLBYE9f53LRVCCbJw1yx8koyiMcJOgFH04tBYUkDXBKnZLkldh4Z2kBnAJ2alO6SVqwrtgiSk9iaQ19EPktwL/RYuQ9c/Et45znB467dUyHAvq3AWgHtccJx+Ev+Ej19G53DBAFu0cc/wu/I2HsEVwA1PhSl1eK4NrxluuGTtJ5QUksmhaCkk68dM1SokGwxuoR0b/Qp5zw/L/xHkHUeiPgAAAABJRU5ErkJggg=="
flag64["ie"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAAUBAMAAAANaGKIAAAAD1BMVEX/iD4Wm2L///+y3sv/176zaFdvAAAAF0lEQVQY02MQBANhJTBwYICAUcHBJAgAHJ0eZQMU55UAAAAASUVORK5CYII=";
flag64["it"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUAgMAAADnxWVXAAAACVBMVEUAkkbOKzf///85rJ3UAAAAFElEQVQI12NgYOBatSo0NIBh6DAATSAu4Xxi9HsAAAAASUVORK5CYII="
flag64["jm"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAAUBAMAAAANaGKIAAAAIVBMVEX/uBwAd0kAAACHYQ6XnS4SDQEZfkT1sBrxrRoef0PWmhdnQ13iAAAAbklEQVQY023RwQ2AMAgF0H+z8eYK7OAKTTx3BQdwBIdwYKEFUhp6fEnD5wPgOsL7ALyLshW0qGInSLSa3WIEmnWYILVHlW1j62hqNnCom2JXN8OuZgH3BbPv2aAs0hy+aHi3ac2skGBWXVpydo4fbqwzeoyE38IAAAAASUVORK5CYII="
flag64["jp"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUBAMAAABohZD3AAAAElBMVEW8AC3////NP2Dmn7DADzn77/GuzSpGAAAAP0lEQVQY02MQRAUM5PGNXJSR+UEMDAyqSHwFIJ8JwRdmAAFDOF8IzFeE80XAfEecfHT16Oah24fhHnT3ku9/AB+iE2XMgOg6AAAAAElFTkSuQmCC"
flag64["lu"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACEAAAAUBAMAAADxfUlCAAAAD1BMVEXtKTkAod7///9VwenzcHusVZA/AAAAIUlEQVQY02NgoCNwQQMODEpoQIGGIsZowIBBEA0I0E4EAL4AHCFvjbcyAAAAAElFTkSuQmCC"
flag64["ma"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUBAMAAABohZD3AAAAFVBMVEXBJy1iQi5MSS+nLi2SNC2rLi15PC6Ld+IEAAAAKElEQVQY02NgGBjggsoNFjRF4TspqaDw2ZQSUPiMggIofGYGg4HxBwB4BQJD/6PdEAAAAABJRU5ErkJggg=="
flag64["mc"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABkAAAAUAQMAAABCuQT+AAAABlBMVEXOESb///9W4q7JAAAAEklEQVQI12NgIBn8//+/gSQCAHAUIuOMnBoSAAAAAElFTkSuQmCC"
flag64["mu"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUAgMAAADnxWVXAAAADFBMVEUApVEaIG3qKDn/1QBAdqXLAAAAHUlEQVQI12NYBQELGIhhhEJAAFGM/xDwgSgGKQAAdktPG8262+oAAAAASUVORK5CYII="
flag64["nl"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUBAMAAABohZD3AAAAD1BMVEUhRotrhLKuHCjIZm7///9fvUPgAAAAHElEQVQY02NUYkABTAzU5bMI4udT2z5GNPNpDQBo2wB0uX4S5QAAAABJRU5ErkJggg=="
flag64["pt"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUCAMAAACtdX32AAAAn1BMVEX/AADzVwDqkQBTkQAAYQD7PT2yweAAZgD4AADjfACQtADCzQD8LS3xaS/ujhzraA/ipQDsmwCbugDdvwCpvwD2WA/qjlLKmVKEqACjuQDT2ADNorbO1+vk4QBKhwDgoifYuADspFr5Vj6MkiCHnRw1fQDwblvtLwDXngDvfSPsQjPNrVu9nKr8Ryj6u7utiFv5czicrteesNe8n6H7u7sxBDfVAAAAhElEQVQoz2NgRwIMmIBe0iwceKSZuSQ1mBhxSTNr64uLqSkyYpcWkeLj4eXV1VTgxCotKcVqIsOmx6rOhE2ahVuCT4fN0JiPU5gDuzSrNJuRNCt2aXYuVS0DGTZeJUFBrHYLcSuL8vCIystidxq7nJCKuBi/AD/uYBERwB0shAKV/vENAM1rDK2atilmAAAAAElFTkSuQmCC"
flag64["re"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUAgMAAADnxWVXAAAACVBMVEUAI5XtKTn///+i/AH+AAAAFElEQVQI12NgYOBatSo0NIBh6DAATSAu4Xxi9HsAAAAASUVORK5CYII="
flag64["ro"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUAgMAAADnxWVXAAAACVBMVEUAK3/OESb80RYeTc2tAAAAFElEQVQI12NgYOBatSo0NIBh6DAATSAu4Xxi9HsAAAAASUVORK5CYII="
flag64["rs"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUCAMAAACtdX32AAAAtFBMVEX////FO0HQZzTltLZykLAXQnbScTnGNjwMQHbANj7p19jjzMzTjY7jwsP47O3bl5XalCXUhCjuxMZtSWbVekOXgJSPd4vPW1rXe1LJUlbannTevsDFeDjVd2Pi0tPcnqHOo6Xq4+PIfoLQm53UqavGenzQbFzepmrcjDrJR0399fbFXTLMTjSJSknVn1WBZHzlyLbYgIO6WDrSfTTXpYzs29vera/x5OTIdnnPgobRh2vTgXFvR69fAAAAo0lEQVQoz73O1w6CQBBA0S24wi5LE6Qj1d57+f//MhGNIbg8ep4muZnJgH4n8B1hZ56tfHF2A7JeTMai7BHbJFNbeNw0TMNYtrJSg3sSHSIIlSYgv/R2caBuER7ITZ98OfvZyNWGgsxoXlRh4ggyT3KuplS0zdmNjgq6EWTMKnwtT63XpJp6V8v0qDtSE3iLySNjCGngt7mn8xBZQMjSsQb+6gluZBOQL+4JdQAAAABJRU5ErkJggg=="
flag64["us"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACYAAAAUCAMAAADWUb86AAAANlBMVEXGWWZ5eJtdQ25tbJI8O25IR3dUU4DZkZqyIjT///+VlbCFhKRgX4mrU2fY1+KaJj+5fpCqqcBFmxQnAAAAh0lEQVQoz8XPSwrDMAxFUau6T0ks9bf/zXYQKBTs4kGhZ6CR0LUbQhAEBOK+DzVchSpK4VI8tqEGqSiZwmXidgw1GaZIWajLaxql406PMnUxjRomEg91PGZRSMLo5+DaxmSk9CRLHfPZGhhR72tff0qS5wNn1y6fZmvHkvZbi9FtSduX/CX6Asb+ET4hHaT8AAAAAElFTkSuQmCC"
flag64["uy"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUCAMAAACtdX32AAAAVFBMVEX///+7iRX07ePOql0dTrGqvOL8+/o5ZLsAOKiOpti0ghru5dfCkyPTs3D69/Xo3MvGnUvZqgzhy5fQnwtPdcPiza7cwILizKPWuInhsBCbsd20xOU60XNuAAAAcklEQVQYGaXBWRLCIBBAwTdAJoRlsrl7/3vqP0qqtJtjqlmVb9x8qd4cnMYGYD6JLFkJsQHmi+ySNuUxNcDVtN5XqZmP9JrKXsrNeA4N0LMvSRZTQmwAzvm6zRnG0OBNLavxk9BF7GLo4sDURexi7OIvL5HoCsLqMEQ5AAAAAElFTkSuQmCC"
flag64["za"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUCAMAAACtdX32AAAAb1BMVEUAd0kJe0/sqRn8txv///9AT6fobWUAAAAAFIngPDH07vKneBFQOQiMwq0SDQLd7ecvg0CAlzE1k27UrSOqsdg+mHX1wL3qd29OXK0SJZHW6eLiSkA5hj7ariKPmy/0u7eHmTAzhD+Xx7TjTEKYyLXXNRCBAAAAj0lEQVQoz32RWRLCIBAFHwQliVGDxn1f7n9GgSzFIEP/dr0upgAA8Vb7T5UEnt26PqR1671YqsclpQuTC6CR2xcfgF4timcf2Jz/AtBaN/J2nQJzgtMucB8DiuB1EIjpdRBgtDS8tue1bNyWDf+0aWoP62YEkGl9LCkg01MZ6+BL4qnTmanTmemgxTc9tfwA2zUQndqOrtoAAAAASUVORK5CYII="

flag64["bb"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAUCAMAAACtdX32AAAAPFBMVEX/xyabeBYzJweRcRX+xiWzjBoeFwQAJn9xWBBAMgloUA9aRgzwuyPksiHOoB7Vph94XhHerCC+lBvyvCQmVMjVAAAAYElEQVQoz82RSw7AIAhEUYGCn/rp/e/anWkace0s5yUwDHBNwdTHOwf3buJyA8QIcJclRh+y1xw8roeTgggoGbuRH5HMaEVLQ2REM3lQZnUmrpQS1c3drW1rce7Yj/3xC6MlDMxrrZFjAAAAAElFTkSuQmCC"
flag64["mx"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACMAAAAUCAMAAAAweHR+AAAAb1BMVEX////X07jb3cSUb1HeX23c383r6tYAaEfOESZVmoR3SSjm5M7Iwq7i2tCdx7yrx8DMtZ6Qqo+0n5R0Vj7PyKLLqnd+Y0r39++wtYzl27He0Mp0nJ/049JkOiKAVDqii4Brq62ahV6ziGBekH+8mHOqo5LtAAAAYklEQVQoz93RNxaAIBBFUYIYEAQkmLP7X6N2NJ6x59W3mH8GFbEKxbIyhhIwnTxX/WMGT/kygiZ3t+WcQqaenQ+h3RhgiDK6tVRiwDDW7JeZMIHuedGhiIB31Vj0eYI//TIPmiIRZ/iengEAAAAASUVORK5CYII="

flag64["noflag"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAANCAMAAACTkM4rAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAEXUExURQAAAJKSktXV1lNTUzs7O4mJibW1tVJSUtPT04iIiVVWVnd3eJqamr6+vuvr6/b29nJzc01NTygnJ8nHx+jo6PDw8Ovr7MrJyCMiIrGwsHx9fVFRUaioqJ2dnU9PT4aGhrOzsyMjIg4ODnd3dyoqKh8fH3h4eG5ubx0dHTMzM4B/fg8PDwQEBHRzc2xtbWlpaY6OjouLjGtra3V1dXd2djAwMKmop9LR0YyMjIyLi9PS0qOjozExMQUFBRkZGYeHiKCgoaKiooqLjH5+fmFhYp+goL2+vnBxcKOjore3tri4t2lqa7i5uZCQkWZmZhISEmlpare3uGpqapGRknx+fy0tLggICCMjJCQkJQkJCSwtLX+AgRsbGxD+1OUAAAAJcEhZcwAADr8AAA6/ATgFUyQAAACfSURBVBhXdcjXAoEAGEDhX5JVIdl7r+w9ighZZe/3fw4u/kvO3fngdwbCSJooykSaLVYkm51mWIeDZWin6z8B52Z5j4f3+jgEAH8gGApHorF4AgEgmUpnsrl8oVhCABDKlWqt3mi2BIRv7U631x8MR7gAojSeyAwjT2eSiKTMF0t1tVY327mCtCM0fX84HHWNOCFJ5wtcb/cHPF9vAPgAEyIU6qDlHbIAAAAASUVORK5CYII="
flag64["shield"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAANCAMAAACTkM4rAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAABUUExURQAAAAUFBQoKCv///wEBAQ0NDQ8PDwMDAw4ODgICAhAQEC8vL6urqwYGBqqqqoGBgQQEBDExMQwMDBgYGM7OzgcHBxsbGxoaGggICB0dHT4+Pj09PdDhOekAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAB5SURBVBhXXY3bDoJADETH6aILaOUqIP//n7RdSYjz0uTMaQvc+BeAlEucpIo2zwirVFD090f29opyfSK3i1U3BYGt8Bno5a2dt48aGpvMt7IzlNiHFg/7wfaAbjRNJyc6umTa/FGXRHSZQzK2bl+Dum/rjzjyQxEAB6niBHSSJ9cvAAAAAElFTkSuQmCC"
flag64["unlicenced"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAANCAMAAACTkM4rAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAABUUExURQAAAAUFBQoKCv///wEBAQ0NDQ8PDwMDAw4ODgICAhAQEC8vL6urqwYGBqqqqoGBgQQEBDExMQwMDBgYGM7OzgcHBxsbGxoaGggICB0dHT4+Pj09PdDhOekAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAB5SURBVBhXXY3bDoJADETH6aILaOUqIP//n7RdSYjz0uTMaQvc+BeAlEucpIo2zwirVFD090f29opyfSK3i1U3BYGt8Bno5a2dt48aGpvMt7IzlNiHFg/7wfaAbjRNJyc6umTa/FGXRHSZQzK2bl+Dum/rjzjyQxEAB6niBHSSJ9cvAAAAAElFTkSuQmCC"

flag64["nabilla.png"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAAUCAYAAAD/Rn+7AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAJVSURBVEhLY2SgHPyH0uiAGmZTZMh/eR42hmMVCQwc4rJQIQQwKu1iePjhM4hJkUPJ0lxopfW/0E6PgVtZGyqCGwin1oIosh3JBKVJAUQ7DgTezm4GUbiSAUFAqgP/P6qIwHAcyHZQSIEwNpdQ4kiSgr7F1eh/nLEa2IHps1YwrDl9FSz+68YpBlYWFgj7928Gdk1zMDvMTIdhemo4mD1n3wmG8uVbSY5qUjSAQ8900jqGl99+Mfy/cw4qjB8wqhgxSPJxMVzprSQrPZIUxR/0nCGOO7UXKkIYgDzy/NM3hmc8klAR0gDRDlxQX8agq6LEsGdKN1QEEjq4ALLc3kUzGHSUFRlmVRVBRYgHRDsw3tsdTLOyQtIaCDAxIbSDHITsKGQ5mJ7UAG8wTQogKQ2CopbRzBkSxUKCUGHCAORwmF4QFyxIJCApDT5YOwvKIh28Pn8EyiINkOLAJ8yMjAz3ysIZ/v77x8Dw8RNUGBJCxsF5DO7p7SjRDAJ///5leDmjkYEZEuV3wIIkAFIcKCvXsYKBhYmRgcXCFWQzVBgCBPiFGcREpaA8BGBRN2VgYWaCFTGqYEESAElRDATg2gBUHoLT4tt3YEFs4P///+DQhNYiIEByIQ0CpDqQCRSKMPCybztGlIIASOz1wsNQHrzBQBYgy1dA8P9vfB0Dk6YCmMNYkcTgYOPLICklz7B81RSG/x3zwOIgAJIDUWAOGYDUEMQKQA46cGQzhuOoAajiQFoCYoN+MTMTY8zWNdkMwPICKkQ68A6cDCyi/i8CMuMhIoQAAwMAyvqlzhVee30AAAAASUVORK5CYII="

flag64["sat"] = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAKMSURBVFhHvddLqE1RHMfxjaSQRxLKO2GuJGXAwKs8xjJhxtREMjCQlBI3E2VgwAATI2XgMSDKwCOMCFFiSF7l9f3uc9ZtnXXWtve+91y/+nT33q7z/5+919pr3eIfWY8beI/5Xvhf2Yw7+BO5gDHNOOzAA8SFg99YgzHJNjxGrnDsHmx04PmMXMGc3Rh49uAXcgVTbzEFdVmA7ViNRndtL5o2cQRVsdhR/ET4fR/dHNSmaRNf4DfMZQaeI/0/19EoTZu4iDh+83Wdw2Iuck3MQ6M0acJpuRjG4qfgtf1eILkmlqNx6prwDTkRoXi4XtXEG0xAq1Q14Rjww9PiQdrEI2wsz0aQtAmL+/MuznSPc+ImWn/zNKEJb7vTyeK5oqnvWIiBZBF85mYFcgVjP+ArfkyyFbmiwUCLz8Jh3MJDXMUJ5AproMVdfj8gV6jKLhgfV3hPjDhuQnJFchxw/nSAOvUcsM4E35hVr+3aOIJfIi0Wc3leiukIsyNM1cBzF7Amq2hf6po4jRCnaFo85lJuw77AejINkzuHZaZ2haxF7gN1GcZn7m3P/U7qPnq2d+/g7Qt5imedwzLh1obnHBuC8T1Rt4DFHB+OsXK3/RUfPejmNdxQhLtwACfhs04fxyaENFlFU275y2/sSdi1nIfnB8uz3sRjwluePs+2TdzE8KKyzxOyEt/gXTgG1/FJCHFaOap9SeXSpokNKFZ1T14hTBU3lPFu+QXapEkT8bgrrsCLDozxXiDe7uO4jbNeaJm6JrZgOLPh4PMfnFpuLgeRqib8C6wvyxAGmLPC5+zjcTb0vTxaJNfETmQzE+cQ7+v1BKNJ3ISfVfuFluAQrsFpegmjjX+BfUK0XBfFX6bvmRNdu2M+AAAAAElFTkSuQmCC"

function getCountryFlag(countryCode) {
    if (flag64[countryCode.toLowerCase()] != null)
        return flag64[countryCode.toLowerCase()]

    var code = countryCode.toUpperCase()

    for (let i = 0; i < mcc.length; i++) {
        if (mcc[i].code == code) {
            return "https://flagcdn.com/h20/" + code + ".png"
        }
    }

    return flag64["shield"];
}

function getTgFlag(id) {
    if (id.length > 2 && parseInt(id) > 100) {
        id = id.substring(0, 3)

        switch (id) {
            case "736":
            case "994":
                return flag64["unlicenced"] // return "unlicenced.png"

            case "206":
                return flag64["be"] // return "be.png"

            case "214":
                return flag64["es"] // return "es.png"

            case "228":
                return flag64["ch"] // return "ch.png"

            case "262":
            case "264":
                return flag64["de"] // return "de.png"

            case "102":
            case "302":
                return flag64["ca"] // return "ca.png"

            case "604":
                return flag64["ma"] // return "ma.png"

            case "340":
            case "546":
            case "547":
            case "742":
            case "647":
            case "208":
                return flag64["fr"] // return "fr.png"
/*
            // if you want to return several flags i.e (region / country)
            case 2623:
                return [ flag64["flag1"], flag64["flag2"]  ]
*/
            default:
                break
        }

        for (let i = 0; i < mcc.length; i++) {
            if (mcc[i].dmrid == id) {
                var code = mcc[i].code.toLowerCase()

                if (flag64[code] != null)
                    return flag64[code]
                
                return "https://flagcdn.com/h20/" + code + ".png"
            }
        }
    }

    return flag64["shield"] // "shield.png"
}

function getFlag(str) {
    if (str.indexOf(" ") == -1) {
        for(let i=0; i < callsigns.length; i++) {
            callsignGroup = callsigns[i].prefix.split(",");

            // AA-AB, DD-EE
            for(let g=0; g < callsignGroup.length; g++) {
                var subGroup = callsignGroup[g].split("-");
                
                if (subGroup.length == 1)
                    subGroup.push(subGroup[0]);

                // AA-AB
                var start = subGroup[0];
                var end = subGroup[1];

                if (start == "F")
                    toto = "france";

                var p = str.substr(0, subGroup[0].length);

                if (p >= start && p <= end) {
                    var code = callsigns[i].code.toLowerCase()

                    if (flag64[code] != null)
                        return flag64[code]

                    return "https://flagcdn.com/h20/" + code + ".png";
                }
            }
        }
    }

    return "shield.png";
}

callsigns = [
    {
			"prefix": "AA-AL",
    	"country": "United States",
			"code": "US"
    }, {
    	"prefix": "AM-AO",
    	"country": "Spain",
			"code": "ES"
    }, {
			"prefix": "AP-AS",
    	"country": "Pakistan",
			"code": "PK"
    }, {
    	"prefix": "AT-AW",
    	"country": "India",
			"code": "IN"
    }, {
    	"prefix": "AX",
    	"country": "Australia",
			"code": "AU"
    }, {
    	"prefix": "AY-AZ",
    	"country": "Argentina",
			"code": "AR"
    }, {
    	"prefix": "A2",
    	"country": "Botswana",
			"code": "BW"
    }, {
    	"prefix": "A3",
    	"country": "Tonga",
			"code": "TO"
    }, {
    	"prefix": "A4",
    	"country": "Oman",
			"code": "OM"
    }, {
    	"prefix": "A5",
    	"country": "Bhutan",
			"code": "BT"
    }, {
    	"prefix": "A6",
    	"country": "United Arab Emirates",
			"code": "AE"
    }, {
    	"prefix": "A7",
    	"country": "Qatar",
			"code": "QA"
    }, {
    	"prefix": "A8",
    	"country": "Liberia",
			"code": "LR"
    }, {
    	"prefix": "A9",
    	"country": "Bahrain",
			"code": "BH"
    }, {
    	"prefix": "B",
    	"country": "China",
			"code": "CN"
    }, {
    	"prefix": "BM-BQ, BU-BX",
    	"country": "Taiwan",
			"code": "TW"
    }, {
    	"prefix": "CA-CE",
    	"country": "Chile",
			"code": "CL"
    }, {
    	"prefix": "CF-CK",
    	"country": "Canada",
			"code": "CA"
    }, {
    	"prefix": "CL-CM",
    	"country": "Cuba",
			"code": "CU"
    }, {
    	"prefix": "CN",
    	"country": "Morocco",
			"code": "MA"
    }, {
    	"prefix": "CO",
    	"country": "Cuba",
			"code": "CU"
    }, {
    	"prefix": "CP",
    	"country": "Bolivia",
			"code": "BO"
    }, {
    	"prefix": "CQ-CU",
    	"country": "Portugal",
			"code": "PT"
    }, {
    	"prefix": "CV-CX",
    	"country": "Uruguay",
			"code": "UY"
    }, {
    	"prefix": "CY-CZ",
    	"country": "Canada",
			"code": "CA"
    }, {
    	"prefix": "C2",
    	"country": "Nauru",
			"code": "NR"
    }, {
    	"prefix": "C3",
    	"country": "Andorra",
			"code": "AD"
    }, {
    	"prefix": "C4",
    	"country": "Cyprus",
			"code": "CY"
    }, {
    	"prefix": "C5",
    	"country": "Gambia",
			"code": "GM"
    }, {
    	"prefix": "C6",
    	"country": "Bahamas",
			"code": "BS"
    }, {
    	"prefix": "C7",
    	"country": "World Meteorological Organization[Note 2]",
			"code": "WW"
    }, {
    	"prefix": "C8-C9",
    	"country": "Mozambique",
			"code": "MZ"
    }, {
    	"prefix": "DA-DR",
    	"country": "Germany",
			"code": "DE"
    }, {
    	"prefix": "DS-DT",
    	"country": "South Korea",
			"code": "KR"
    }, {
    	"prefix": "DU-DZ",
    	"country": "Philippines",
			"code": "PH"
    }, {
    	"prefix": "D2-D3",
    	"country": "Angola",
			"code": "AO"
    }, {
    	"prefix": "D4",
    	"country": "Cape Verde",
			"code": "CV"
    }, {
    	"prefix": "D5",
    	"country": "Liberia",
			"code": "LR"
    }, {
    	"prefix": "D6",
    	"country": "Comoros",
			"code": "KM"
    }, {
    	"prefix": "D7-D9",
    	"country": "South Korea",
			"code": "KR"
    }, {
    	"prefix": "EA-EH",
    	"country": "Spain",
			"code": "ES"
    }, {
    	"prefix": "EI-EJ",
    	"country": "Ireland",
			"code": "IE"
    }, {
    	"prefix": "EK",
    	"country": "Armenia",
			"code": "AM"
    }, {
    	"prefix": "EL",
    	"country": "Liberia",
			"code": "LR"
    }, {
    	"prefix": "EM-EO",
    	"country": "Ukraine",
			"code": "UA"
    }, {
    	"prefix": "EP-EQ",
    	"country": "Iran",
			"code": "IR"
    }, {
    	"prefix": "ER",
    	"country": "Moldova",
			"code": "MD"
    }, {
    	"prefix": "ES",
    	"country": "Estonia",
			"code": "EE"
    }, {
    	"prefix": "ET",
    	"country": "Ethiopia",
			"code": "ET"
    }, {
    	"prefix": "EU-EW",
    	"country": "Belarus",
			"code": "BY"
    }, {
    	"prefix": "EX",
    	"country": "Kyrgyzstan",
			"code": "KG"
    }, {
    	"prefix": "EY",
    	"country": "Tajikistan",
			"code": "TJ"
    }, {
    	"prefix": "EZ",
    	"country": "Turkmenistan",
			"code": "TM"
    }, {
    	"prefix": "E2",
    	"country": "Thailand",
			"code": "TH"
    }, {
    	"prefix": "E3",
    	"country": "Eritrea",
			"code": "ER"
    }, {
    	"prefix": "E4",
    	"country": "Palestinian Authority",
			"code": "PS"
    }, {
    	"prefix": "E5",
    	"country": "Cook Islands",
			"code": "CK"
    }, {
    	"prefix": "E6",
    	"country": "Niue",
			"code": "NU"
    }, {
    	"prefix": "E7",
    	"country": "Bosnia and Herzegovina",
			"code": "BA"
    }, {
    	"prefix": "F",
    	"country": "France",
			"code": "FR"
    }, {
    	"prefix": "G",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "HA",
    	"country": "Hungary",
			"code": "HU"
    }, {
    	"prefix": "HB",
    	"country": "Switzerland",
			"code": "CH"
    }, {
    	"prefix": "HB0, HB3Y, HBL",
    	"country": "Liechtenstein",
			"code": "LI"
    }, {
    	"prefix": "HC-HD",
    	"country": "Ecuador",
			"code": "EC"
    }, {
    	"prefix": "HE",
    	"country": "Switzerland",
			"code": "CH"
    }, {
    	"prefix": "HF",
    	"country": "Poland",
			"code": "PL"
    }, {
    	"prefix": "HG",
    	"country": "Hungary",
			"code": "HU"
    }, {
    	"prefix": "HH",
    	"country": "Haiti",
			"code": "HT"
    }, {
    	"prefix": "HI",
    	"country": "Dominican Republic",
			"code": "DO"
    }, {
    	"prefix": "HJ-HK",
    	"country": "Colombia",
			"code": "CO"
    }, {
    	"prefix": "HL",
    	"country": "South Korea",
			"code": "KR"
    }, {
    	"prefix": "HM",
    	"country": "North Korea",
			"code": "KP"
    }, {
    	"prefix": "HN",
    	"country": "Iraq",
			"code": "IQ"
    }, {
    	"prefix": "HO-HP",
    	"country": "Panama",
			"code": "PA"
    }, {
    	"prefix": "HQ-HR",
    	"country": "Honduras",
			"code": "HN"
    }, {
    	"prefix": "HS",
    	"country": "Thailand",
			"code": "TH"
    }, {
    	"prefix": "HT",
    	"country": "Nicaragua",
			"code": "NI"
    }, {
    	"prefix": "HU",
    	"country": "El Salvador",
			"code": "SV"
    }, {
    	"prefix": "HV",
    	"country": "Vatican City",
			"code": "VA"
    }, {
    	"prefix": "HW-HY",
    	"country": "France",
			"code": "FR"
    }, {
    	"prefix": "HZ",
    	"country": "Saudi Arabia",
			"code": "SA"
    }, {
    	"prefix": "H2",
    	"country": "Cyprus",
			"code": "CY"
    }, {
    	"prefix": "H3",
    	"country": "Panama",
			"code": "PA"
    }, {
    	"prefix": "H4",
    	"country": "Solomon Islands",
			"code": "SB"
    }, {
    	"prefix": "H6-H7",
    	"country": "Nicaragua",
			"code": "NI"
    }, {
    	"prefix": "H8-H9",
    	"country": "Panama",
			"code": "PA"
    }, {
    	"prefix": "I",
    	"country": "Italy",
			"code": "IT"
    }, {
    	"prefix": "JA-JS",
    	"country": "Japan",
			"code": "JP"
    }, {
    	"prefix": "JT-JV",
    	"country": "Mongolia",
			"code": "MN"
    }, {
    	"prefix": "JW-JX",
    	"country": "Norway",
			"code": "NO"
    }, {
    	"prefix": "JY",
    	"country": "Jordan",
			"code": "JO"
    }, {
    	"prefix": "JZ",
    	"country": "Indonesia",
			"code": "ID"
    }, {
    	"prefix": "J2",
    	"country": "Djibouti",
			"code": "DJ"
    }, {
    	"prefix": "J3",
    	"country": "Grenada",
			"code": "GD"
    }, {
    	"prefix": "J4",
    	"country": "Greece",
			"code": "GR"
    }, {
    	"prefix": "J5",
    	"country": "Guinea-Bissau",
			"code": "GW"
    }, {
    	"prefix": "J6",
    	"country": "Saint Lucia",
			"code": "LC"
    }, {
    	"prefix": "J7",
    	"country": "Dominica",
			"code": "DM"
    }, {
    	"prefix": "J8",
    	"country": "Saint Vincent and the Grenadines",
			"code": "VC"
    }, {
    	"prefix": "K",
    	"country": "United States",
			"code": "US"
    }, {
    	"prefix": "LA-LN",
    	"country": "Norway",
			"code": "NO"
    }, {
    	"prefix": "LO-LW",
    	"country": "Argentina",
			"code": "AR"
    }, {
    	"prefix": "LX",
    	"country": "Luxembourg",
			"code": "LU"
    }, {
    	"prefix": "LY",
    	"country": "Lithuania",
			"code": "LT"
    }, {
    	"prefix": "LZ",
    	"country": "Bulgaria",
			"code": "BG"
    }, {
    	"prefix": "L2-L9",
    	"country": "Argentina",
			"code": "AR"
    }, {
    	"prefix": "M",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "N",
    	"country": "United States",
			"code": "US"
    }, {
    	"prefix": "OA-OC",
    	"country": "Peru",
			"code": "PE"
    }, {
    	"prefix": "OD",
    	"country": "Lebanon",
			"code": "LB"
    }, {
    	"prefix": "OE",
    	"country": "Austria",
			"code": "AT"
    }, {
    	"prefix": "OF-OJ",
    	"country": "Finland",
			"code": "FI"
    }, {
    	"prefix": "OK-OL",
    	"country": "Czech Republic",
			"code": "CZ"
    }, {
    	"prefix": "OM",
    	"country": "Slovakia",
			"code": "SK"
    }, {
    	"prefix": "ON-OT",
    	"country": "Belgium",
			"code": "BE"
    }, {
    	"prefix": "OU-OZ",
    	"country": "Denmark",
			"code": "DK"
    }, {
    	"prefix": "PA-PI",
    	"country": "Netherlands",
			"code": "NL"
    }, {
    	"prefix": "PJ",
    	"country": "Former Netherlands Antilles",
			"code": "BQ"
    }, {
    	"prefix": "PK-PO",
    	"country": "Indonesia",
			"code": "ID"
    }, {
    	"prefix": "PP-PY",
    	"country": "Brazil",
			"code": "BR"
    }, {
    	"prefix": "PZ",
    	"country": "Suriname",
			"code": "SR"
    }, {
    	"prefix": "P2",
    	"country": "Papua New Guinea",
			"code": "PG"
    }, {
    	"prefix": "P3",
    	"country": "Cyprus",
			"code": "CY"
    }, {
    	"prefix": "P4",
    	"country": "Aruba",
			"code": "AW"
    }, {
    	"prefix": "P5-P9",
    	"country": "North Korea",
			"code": "KP"
    }, {
    	"prefix": "R",
    	"country": "Russian Federation",
			"code": "RU"
    }, {
    	"prefix": "SA-SM",
    	"country": "Sweden",
			"code": "SE"
    }, {
    	"prefix": "SN-SR",
    	"country": "Poland",
			"code": "PL"
    }, {
    	"prefix": "SSA-SSM",
    	"country": "Egypt",
			"code": "EG"
    }, {
    	"prefix": "SSN-STZ",
    	"country": "Sudan",
			"code": "SD"
    }, {
    	"prefix": "SU",
    	"country": "Egypt",
			"code": "EG"
    }, {
    	"prefix": "SV-SZ",
    	"country": "Greece",
			"code": "GR"
    }, {
    	"prefix": "S2-S3",
    	"country": "Bangladesh",
			"code": "BD"
    }, {
    	"prefix": "S5",
    	"country": "Slovenia",
			"code": "SI"
    }, {
    	"prefix": "S6",
    	"country": "Singapore",
			"code": "SG"
    }, {
    	"prefix": "S7",
    	"country": "Seychelles",
			"code": "SC"
    }, {
    	"prefix": "S8",
    	"country": "South Africa",
			"code": "ZA"
    }, {
    	"prefix": "S9",
    	"country": "São Tomé and Príncipe",
			"code": "ST"
    }, {
    	"prefix": "TA-TC",
    	"country": "Turkey",
			"code": "TR"
    }, {
    	"prefix": "TD",
    	"country": "Guatemala",
			"code": "GT"
    }, {
    	"prefix": "TE",
    	"country": "Costa Rica",
			"code": "CR"
    }, {
    	"prefix": "TF",
    	"country": "Iceland",
			"code": "IS"
    }, {
    	"prefix": "TG",
    	"country": "Guatemala",
			"code": "GT"
    }, {
    	"prefix": "TH",
    	"country": "France",
			"code": "FR"
    }, {
    	"prefix": "TI",
    	"country": "Costa Rica",
			"code": "CR"
    }, {
    	"prefix": "TJ",
    	"country": "Cameroon",
			"code": "CM"
    }, {
    	"prefix": "TK",
    	"country": "France",
			"code": "FR"
    }, {
    	"prefix": "TL",
    	"country": "Central African Republic",
			"code": "CF"
    }, {
    	"prefix": "TM",
    	"country": "France",
			"code": "FR"
    }, {
    	"prefix": "TN",
    	"country": "Republic of the Congo",
			"code": "CG"
    }, {
    	"prefix": "TO-TQ",
    	"country": "France",
			"code": "FR"
    }, {
    	"prefix": "TR",
    	"country": "Gabon",
			"code": "GA"
    }, {
    	"prefix": "TS",
    	"country": "Tunisia",
			"code": "TN"
    }, {
    	"prefix": "TT",
    	"country": "Chad",
			"code": "TD"
    }, {
    	"prefix": "TU",
    	"country": "Ivory Coast",
			"code": "CI"
    }, {
    	"prefix": "TV-TX",
    	"country": "France",
			"code": "FR"
    }, {
    	"prefix": "TY",
    	"country": "Benin",
			"code": "BJ"
    }, {
    	"prefix": "TZ",
    	"country": "Mali",
			"code": "ML"
    }, {
    	"prefix": "T2",
    	"country": "Tuvalu",
			"code": "TV"
    }, {
    	"prefix": "T3",
    	"country": "Kiribati",
			"code": "KI"
    }, {
    	"prefix": "T4",
    	"country": "Cuba",
			"code": "CU"
    }, {
    	"prefix": "T5",
    	"country": "Somalia",
			"code": "SO"
    }, {
    	"prefix": "T6",
    	"country": "Afghanistan",
			"code": "AF"
    }, {
    	"prefix": "T7",
    	"country": "San Marino",
			"code": "SM"
    }, {
    	"prefix": "T8",
    	"country": "Palau",
			"code": "PW"
    }, {
    	"prefix": "UA-UI",
			"country": "Russian Federation",
			"code": "RU"
			}, {
    	"prefix": "UJ-UM",
    	"country": "Uzbekistan",
			"code": "UZ"
    }, {
    	"prefix": "UN-UQ",
    	"country": "Kazakhstan",
			"code": "KZ"
    }, {
    	"prefix": "UR-UZ",
    	"country": "Ukraine",
			"code": "UA"
    }, {
    	"prefix": "VA-VG",
    	"country": "Canada",
			"code": "CA"
    }, {
    	"prefix": "VH-VN",
    	"country": "Australia",
			"code": "AU"
    }, {
    	"prefix": "VO",
    	"country": "Canada",
			"code": "CA"
    }, {
    	"prefix": "VP-VQ",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "VR",
    	"country": "Hong Kong",
			"code": "HK"
    }, {
    	"prefix": "VS",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "VT-VW",
    	"country": "India",
			"code": "IN"
    }, {
    	"prefix": "VX-VY",
    	"country": "Canada",
			"code": "CA"
    }, {
    	"prefix": "VZ",
    	"country": "Australia",
			"code": "AU"
    }, {
    	"prefix": "V2",
    	"country": "Antigua and Barbuda",
			"code": "AG"
    }, {
    	"prefix": "V3",
    	"country": "Belize",
			"code": "BZ"
    }, {
    	"prefix": "V4",
    	"country": "Saint Kitts and Nevis",
			"code": "KN"
    }, {
    	"prefix": "V5",
    	"country": "Namibia",
			"code": "NA"
    }, {
    	"prefix": "V6",
    	"country": "Federated States of Micronesia",
			"code": "FM"
    }, {
    	"prefix": "V7",
    	"country": "Marshall Islands",
			"code": "MH"
    }, {
    	"prefix": "V8",
    	"country": "Brunei",
			"code": "BN"
    }, {
    	"prefix": "W",
    	"country": "United States",
			"code": "US"
    }, {
    	"prefix": "XA-XI",
    	"country": "Mexico",
			"code": "MX"
    }, {
    	"prefix": "XJ-XO",
    	"country": "Canada",
			"code": "CA"
    }, {
    	"prefix": "XP",
    	"country": "Denmark",
			"code": "DK"
    }, {
    	"prefix": "XQ-XR",
    	"country": "Chile",
			"code": "CL"
    }, {
    	"prefix": "XS",
    	"country": "China",
			"code": "CN"
    }, {
    	"prefix": "XT",
    	"country": "Burkina Faso",
			"code": "BF"
    }, {
    	"prefix": "XU",
    	"country": "Cambodia",
			"code": "KH"
    }, {
    	"prefix": "XV",
    	"country": "Vietnam",
			"code": "VN"
    }, {
    	"prefix": "XW",
    	"country": "Laos",
			"code": "LA"
    }, {
    	"prefix": "XX",
    	"country": "Macao",
			"code": "MO"
    }, {
    	"prefix": "XY-XZ",
			"country": "Myanmar",
			"code": "MM"
		}, {
    	"prefix": "YA",
			"country": "Afghanistan",
			"code": "AF"
		}, {
    	"prefix": "YB-YH",
    	"country": "Indonesia",
			"code": "ID"
    }, {
    	"prefix": "YI",
    	"country": "Iraq",
			"code": "IQ"
    }, {
    	"prefix": "YJ",
    	"country": "Vanuatu",
			"code": "VU"
    }, {
    	"prefix": "YK",
    	"country": "Syria",
			"code": "SY"
    }, {
    	"prefix": "YL",
    	"country": "Latvia",
			"code": "LV"
    }, {
    	"prefix": "YM",
    	"country": "Turkey",
			"code": "TR"
    }, {
    	"prefix": "YN",
    	"country": "Nicaragua",
			"code": "NI"
    }, {
    	"prefix": "YO-YR",
    	"country": "Romania",
			"code": "RO"
    }, {
    	"prefix": "YS",
    	"country": "El Salvador",
			"code": "SV"
    }, {
    	"prefix": "YT-YU",
    	"country": "Serbia",
			"code": "RS"
    }, {
    	"prefix": "YV-YY",
    	"country": "Venezuela",
			"code": "VE"
    }, {
    	"prefix": "Y2-Y9",
    	"country": "Germany",
			"code": "DE"
    }, {
    	"prefix": "ZA",
    	"country": "Albania",
			"code": "AL"
    }, {
    	"prefix": "ZB-ZJ",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "ZK-ZM",
    	"country": "New Zealand",
			"code": "NZ"
    }, {
    	"prefix": "ZN-ZO",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "ZP",
    	"country": "Paraguay",
			"code": "PY"
    }, {
    	"prefix": "ZQ",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "ZR-ZU",
    	"country": "South Africa",
			"code": "ZA"
    }, {
    	"prefix": "ZV-ZZ",
    	"country": "Brazil",
			"code": "BR"
    }, {
    	"prefix": "Z2",
    	"country": "Zimbabwe",
			"code": "ZW"
    }, {
    	"prefix": "Z3",
    	"country": "North Macedonia",
			"code": "MK"
    }, {
    	"prefix": "Z8",
    	"country": "South Sudan",
			"code": "SS"
    }, {
    	"prefix": "2",
    	"country": "United Kingdom",
			"code": "GB"
    }, {
    	"prefix": "3A",
    	"country": "Monaco",
			"code": "MC"
    }, {
    	"prefix": "3B",
    	"country": "Mauritius",
			"code": "MU"
    }, {
    	"prefix": "3C",
    	"country": "Equatorial Guinea",
			"code": "GQ"
    }, {
    	"prefix": "3DA-3DM",
    	"country": "Eswatini",
			"code": "SZ"
    }, {
    	"prefix": "3DN-3DZ",
    	"country": "Fiji",
			"code": "FJ"
    }, {
    	"prefix": "3E-3F",
    	"country": "Panama",
			"code": "PA"
    }, {
    	"prefix": "3G",
    	"country": "Chile",
			"code": "CL"
    }, {
    	"prefix": "3H-3U",
    	"country": "China",
			"code": "CN"
    }, {
    	"prefix": "3V",
    	"country": "Tunisia",
			"code": "TN"
    }, {
    	"prefix": "3W",
    	"country": "Vietnam",
			"code": "VN"
    }, {
    	"prefix": "3X",
    	"country": "Guinea",
			"code": "GN"
    }, {
    	"prefix": "3Y",
    	"country": "Norway",
			"code": "NO"
    }, {
    	"prefix": "3Z",
    	"country": "Poland",
			"code": "PL"
    }, {
    	"prefix": "4A-4C",
    	"country": "Mexico",
			"code": "MX"
    }, {
    	"prefix": "4D-4I",
    	"country": "Philippines",
			"code": "PH"
    }, {
    	"prefix": "4J-4K",
    	"country": "Azerbaijan",
			"code": "AZ"
    }, {
    	"prefix": "4L",
    	"country": "Georgia",
			"code": "GE"
    }, {
    	"prefix": "4M",
    	"country": "Venezuela",
			"code": "VE"
    }, {
    	"prefix": "4O",
    	"country": "Montenegro",
			"code": "ME"
    }, {
    	"prefix": "4P-4S",
    	"country": "Sri Lanka",
			"code": "LK"			
    }, {
    	"prefix": "4T",
    	"country": "Peru",
			"code": "PE"
    }, {
    	"prefix": "4U",
    	"country": "United Nations",
			"code": "UN"
    }, {
    	"prefix": "4V",
    	"country": "Haiti",
			"code": "HT"
    }, {
    	"prefix": "4W",
			"country": "East Timor",
			"code": "TL"
			}, {
    	"prefix": "4X",
    	"country": "Israel",
			"code": "IL"
    }, {
    	"prefix": "4Y",
    	"country": "International Civil Aviation Organization",
			"code": "ICAO"
    }, {
    	"prefix": "4Z",
    	"country": "Israel",
			"code": "IL"
    }, {
    	"prefix": "5A",
    	"country": "Libya",
			"code": "LY"
    }, {
    	"prefix": "5B",
    	"country": "Cyprus",
			"code": "CY"
    }, {
    	"prefix": "5C-5G",
    	"country": "Morocco",
			"code": "MA"
    }, {
    	"prefix": "5H-5I",
    	"country": "Tanzania",
			"code": "TZ"
    }, {
    	"prefix": "5J-5K",
    	"country": "Colombia",
			"code": "CO"
    }, {
    	"prefix": "5L-5M",
    	"country": "Liberia",
			"code": "LR"
    }, {
    	"prefix": "5N-5O",
    	"country": "Nigeria",
			"code": "NG"
    }, {
    	"prefix": "5P-5Q",
    	"country": "Denmark",
			"code": "DK"
    }, {
    	"prefix": "5R-5S",
    	"country": "Madagascar",
			"code": "MG"
    }, {
    	"prefix": "5T",
    	"country": "Mauritania",
			"code": "MR"
    }, {
    	"prefix": "5U",
    	"country": "Niger",
			"code": "NE"
    }, {
    	"prefix": "5V",
    	"country": "Togo",
			"code": "TG"
    }, {
    	"prefix": "5W",
    	"country": "Western Samoa",
			"code": "WS"
    }, {
    	"prefix": "5X",
    	"country": "Uganda",
			"code": "UG"
    }, {
    	"prefix": "5Y-5Z",
    	"country": "Kenya",
			"code": "KE"
    }, {
    	"prefix": "6A-6B",
    	"country": "Egypt",
			"code": "EG"
    }, {
    	"prefix": "6C",
    	"country": "Syria",
			"code": "SY"
    }, {
    	"prefix": "6D-6J",
    	"country": "Mexico",
			"code": "MX"
    }, {
    	"prefix": "6K-6N",
    	"country": "South Korea",
			"code": "KR"
    }, {
    	"prefix": "6O",
    	"country": "Somalia",
			"code": "SO"
    }, {
    	"prefix": "6P-6S",
    	"country": "Pakistan",
			"code": "PK"
    }, {
    	"prefix": "6T-6U",
    	"country": "Sudan",
			"code": "SD"
    }, {
    	"prefix": "6V-6W",
    	"country": "Senegal",
			"code": "SN"
    }, {
    	"prefix": "6X",
    	"country": "Madagascar",
			"code": "MG"
    }, {
    	"prefix": "6Y",
    	"country": "Jamaica",
			"code": "JM"
    }, {
    	"prefix": "6Z",
    	"country": "Liberia",
			"code": "LR"
    }, {
    	"prefix": "7A-7I",
    	"country": "Indonesia",
			"code": "ID"
    }, {
    	"prefix": "7J-7N",
    	"country": "Japan",
			"code": "JP"
    }, {
    	"prefix": "7O",
    	"country": "Yemen",
			"code": "YE"
    }, {
    	"prefix": "7P",
    	"country": "Lesotho",
			"code": "LS"
    }, {
    	"prefix": "7Q",
    	"country": "Malawi",
			"code": "MW"
    }, {
    	"prefix": "7R",
    	"country": "Algeria",
			"code": "DZ"
    }, {
    	"prefix": "7S",
    	"country": "Sweden",
			"code": "SE"
    }, {
    	"prefix": "7T-7Y",
    	"country": "Algeria",
			"code": "DZ"
    }, {
    	"prefix": "7Z",
    	"country": "Saudi Arabia",
			"code": "SA"
    }, {
    	"prefix": "8A-8I",
    	"country": "Indonesia",
			"code": "ID"
    }, {
    	"prefix": "8J-8N",
    	"country": "Japan",
			"code": "JP"
    }, {
    	"prefix": "8O",
    	"country": "Botswana",
			"code": "BW"
    }, {
    	"prefix": "8P",
    	"country": "Barbados",
			"code": "BB"
    }, {
    	"prefix": "8Q",
    	"country": "Maldives",
			"code": "MV"
    }, {
    	"prefix": "8R",
    	"country": "Guyana",
			"code": "GY"
    }, {
    	"prefix": "8S",
    	"country": "Sweden",
			"code": "SE"
    }, {
    	"prefix": "8T-8Y",
    	"country": "India",
			"code": "IN"
    }, {
    	"prefix": "8Z",
    	"country": "Saudi Arabia",
			"code": "SA"
    }, {
    	"prefix": "9A",
    	"country": "Croatia",
			"code": "HR"
    }, {
    	"prefix": "9B-9D",
    	"country": "Iran",
			"code": "IR"
    }, {
    	"prefix": "9E-9F",
    	"country": "Ethiopia",
			"code": "ET"
    }, {
    	"prefix": "9G",
    	"country": "Ghana",
			"code": "GH"
    }, {
    	"prefix": "9H",
    	"country": "Malta",
			"code": "MT"
    }, {
    	"prefix": "9I-9J",
    	"country": "Zambia",
			"code": "ZM"
    }, {
    	"prefix": "9K",
    	"country": "Kuwait",
			"code": "KW"
    }, {
    	"prefix": "9L",
    	"country": "Sierra Leone",
			"code": "SL"
    }, {
    	"prefix": "9M",
    	"country": "Malaysia",
			"code": "MY"
    }, {
    	"prefix": "9N",
    	"country": "Nepal",
			"code": "NP"
    }, {
    	"prefix": "9O-9T",
    	"country": "Democratic Republic of the Congo",
			"code": "CD"
    }, {
    	"prefix": "9U",
    	"country": "Burundi",
			"code": "BI"
    }, {
    	"prefix": "9V",
    	"country": "Singapore",
			"code": "SG"
    }, {
    	"prefix": "9W",
    	"country": "Malaysia",
			"code": "MY"
    }, {
    	"prefix": "9X",
    	"country": "Rwanda",
			"code": "RW"
    }, {
    	"prefix": "9Y-9Z",
    	"country": "Trinidad and Tobago",
			"code": "TT"
    }
];
