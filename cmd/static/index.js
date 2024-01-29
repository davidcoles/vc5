var currents = {};
var lastms = 0;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

var getJSON = function(url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.responseType = 'json';
    xhr.onload = function() {
	var status = xhr.status;
	if (status === 200) {
	    callback(null, xhr.response);
	} else {
	    callback(status, xhr.response);
	}
    };
    xhr.send();
};

function dhms(s) { // s - seconds
    var days = Math.floor(s / 86400);
    var hours = Math.floor((s % 86400) / 3600);
    var minutes = Math.floor((s % 3600) / 60);	
    var seconds = Math.floor(s % 60);
    var start = false
    var dhms = ""
    
    if(days > 0) {
	dhms += days + "d"
	start = true
    }
    
    if(start || hours > 0) {
	dhms += hours + "h"
	if(start) {
	    return dhms
	}
	start = true
    }
    
    if(start || minutes > 0) {
	dhms += minutes + "m"
	if(start) {
	    return dhms
	}
    }
    
    dhms += seconds + "s"
    return dhms
}


function append(p, type, html, c) {
    var e = document.createElement(type)
    if(c !== undefined) {
	e.setAttribute("class", c)
    }
    if(html !== undefined && html !== null) {
	e.innerHTML = html
    }
    p.appendChild(e)
    return e
}

function esc(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function spc(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, "&nbsp;");
}

function tsf(num) {
    var suffix = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'];
    
    if(num < 1000) {
	return num.toString() + " ";
    }
    
    for(; num > 1000 && suffix.length > 1;) {
	num /= 1000
	suffix.shift()
    }

    if(num >= 100) {
	return Math.round(num).toString() + " " + suffix[0]
    }

    if(num > 10) {
        return num.toFixed(1) + " " + suffix[0]
    }
    
    return num.toFixed(2) + " " + suffix[0]
}


function updateStatus(url) {
    getJSON(url, function(err, data) {
        if (err !== null) {
            console.log('Something went wrong: ' + err)
        } else {

	    var summary = summary_t(data.summary)

	    var services = document.createElement("div");
	    
            var vips = document.createElement("div");
	    
	    var rib = {}

	    if(data.rib != undefined) {
		for(var vip of data.rib) {
		    rib[vip] = true
		}
	    }
	    
	    vips.appendChild(vips_t(data.vip))
	    
            //for(var vip in data.services) {
            for(var v of data.vip) {
		var vip = v.vip
		services.appendChild(serv(v, vip, data.services[vip], rib[vip] ? true : false))
		append(services, "div", "&nbsp;")
	    }
	    
	    document.getElementById("vips").replaceWith(vips);
	    vips.id = "vips";

	    document.getElementById("summary").replaceWith(summary);
	    summary.id = "summary";
	    
            document.getElementById("services").replaceWith(services);
            services.id = "services";
	}
    })    
}

function vips_t(vips) {
    var t = document.createElement("table");
    var th = append(t, "tr", null, "hd")
    append(th, "th", "VIP")
    append(th, "th", "State")
    append(th, "th", "Traffic")
    append(th, "th", "Packets")
    append(th, "th", "Rate")
    append(th, "th", "Active")


    var row = function(v) {
	var tr = append(t, "tr", null, v.up ? "up" : "dn")
	append(tr, "td", `<a href="#`+v.vip+`">`+v.vip+`</a>`)
	append(tr, "td", v.up ? "UP" : "DOWN")
	append(tr, "td", tsf(v.stats.octets_per_second*8)+"bits/s")
	append(tr, "td", tsf(v.stats.packets_per_second)+"packets/s")
	append(tr, "td", tsf(v.stats.flows_per_second)+"conns/s")
	append(tr, "td", spc(v.stats.current), "ar")
    }
    
    for(var v of vips) {
	if(!v.up) row(v)
    }
    
    for(var v of vips) {
	if(v.up) row(v)
    }

    return t
}

function summary_t(s) {
    var div = document.createElement("div");
    var t = append(div, "table")
    var hd = append(t, "tr", null, "hd")
    var tr = append(t, "tr", null, "up")
    
    append(hd, "th", "Latency")
    append(tr, "td", s.latency_ns+"ns")
    
    //append(hd, "th", "Dropped")
    //append(tr, "td", tsf(s.dropped_per_second)+"packets/s")
    
    //append(hd, "th", "Blocked")
    //append(tr, "td", tsf(s.blocked_per_second)+"packets/s")

    append(hd, "th", "Bandwidth")
    append(tr, "td", tsf(s.octets_per_second*8)+"bits/s")

    append(hd, "th", "Packets")
    append(tr, "td", tsf(s.packets_per_second)+"packets/s")

    append(hd, "th", "Connection rate")
    append(tr, "td", tsf(s.flows_per_second)+"conns/s")

    append(hd, "th", "Active connections")
    append(tr, "td", spc(s.current), "ar")
    
    return div
}

function serv(v, _vip, list, up) {
    var vip = v.vip
    
    var div = document.createElement("div");
    var t = append(div, "table")
    var tr = append(t, "tr", null, v.up ? "up" : "dn")

    append(tr, "th", v.vip, "ip")
    append(tr, "th", v.up ? "UP" : "DOWN")
    append(tr, "th", tsf(v.stats.octets_per_second*8)+"bits/s")
    append(tr, "th", tsf(v.stats.packets_per_second)+"packets/s")
    append(tr, "th", tsf(v.stats.flows_per_second)+"conns/s")
    append(tr, "th", spc(v.stats.current), "ar")
    
    append(div, "div", "&nbsp;")
    
    t.setAttribute("id", vip)

    for(var s of list) {
	var t = append(div, "table")
	var tr = append(t, "tr", null, "hd")

	var title = esc(s.description) + " [" + s.available + "/" +s.destinations.length + " available - " + s.required + " required]"
	
	append(tr, "th", esc(s.name))
	append(tr, "th", esc(title)).setAttribute("colspan", 4)
	append(tr, "th", "Active")


	tr = append(t, "tr", null, s.available >= s.required ? "up" : "dn")
	append(tr, "th", s.address+":"+s.port+":"+s.protocol)
	append(tr, "th",  dhms(s.for) + " " + (s.up ? "UP" : "DOWN"))
	append(tr, "th", tsf(s.stats.octets_per_second*8)+"bits/s")
	append(tr, "th", tsf(s.stats.packets_per_second)+"packets/s")
	append(tr, "th", tsf(s.stats.flows_per_second)+"conns/s")
	append(tr, "th", spc(s.stats.current), "ar")

	for(var d of s.destinations) {
	    var c = d.disabled ? "ds" : d.up ? "up" : "dn"

	    var address = document.createElement("span")
            address.setAttribute("title", d.mac)
	    address.innerHTML =  d.address+":"+d.port

	    var status = document.createElement("span")
            status.setAttribute("title", "Last check: " + d.diagnostic)
	    status.innerHTML =  dhms(d.for) + " " + (d.up ? "UP" : "DOWN") + " ("+d.took+"ms)"

	    var tr = append(t, "tr", null, c)
	    append(tr, "td").appendChild(address)
	    append(tr, "td").appendChild(status)	    
	    append(tr, "td", spc(d.stats.octets_per_second*8), "ar")
	    append(tr, "td", spc(d.stats.packets_per_second), "ar")
	    append(tr, "td", spc(d.stats.flows_per_second), "ar")
	    append(tr, "td", spc(d.stats.current), "ar")	    
	}

	append(div, "div", "&nbsp;")
    }
    
    return div
}



var lastlog = 0;

function lb() {
    
    //var url = window.location.href + 'stats.json';
    var url = '/status.json';
    var log = '/log/';    
    //var log = window.location.href + 'log/';    

    console.log(url)
    function refresh() {
	updateStatus(url);
	updateLogs(log);
	setTimeout(refresh, 2000);
    }

    setTimeout(refresh, 100);
}

window.lb = lb;




function addMessage(msg) {
    var consoleElement = document.querySelectorAll('#console')[0];
    var messageElement = document.createElement('div');
    messageElement.innerHTML = msg;
    if(consoleElement.childElementCount > 1000 ) {
        consoleElement.removeChild(consoleElement.lastChild);
    }
    consoleElement.insertBefore(messageElement, consoleElement.firstChild);
}

function updateLogs(url) {

    getJSON(url+lastlog, function(err, data) {
        if (err !== null) {
            //alert('Something went wrong: ' + err);
        } else {
            data.forEach(function(item, index) {
                //console.log(index);
                //if(item.Level < 7) {
                    lastlog = item.indx;
                    var date = new Date(item.time*1000);
                    var time = date.toLocaleString();
                    addMessage(time + ": " + item.text);
                //}
            })
        }
    })
}
