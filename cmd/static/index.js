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

function spc(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, "&nbsp;");
}

function tsf(num) {
    var suffix = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'];
    
    if(num < 1000) {
	return num.toString();
    }
    
    for(; num > 1000 && suffix.length > 1;) {
	num /= 1000
	suffix.shift()
    }

    if(num >= 100) {
	return Math.round(num).toString() + suffix[0]
    }

    if(num > 10) {
        return num.toFixed(1) + suffix[0]
    }
    
    return num.toFixed(2) + suffix[0]
}


function updateStats(url) {
    

    getJSON(url, function(err, data) {	
	if (err !== null) {
	    console.log('Something went wrong: ' + err)
	} else {
	    
	    var summary = document.createElement("div");
	    var t = append(summary, "table")
	    var tr = append(t, "tr", null, "hd")
	    
	    append(tr, "th", "Readiness Level")
	    append(tr, "th", "Latency")
	    append(tr, "th", "Bandwidth")
	    append(tr, "th", "Packets")
	    append(tr, "th", "New flows")
	    append(tr, "th", "Concurrent conns")
	    
	    tr = append(t, "tr", null, "up")

	    append(tr, "td", "DEFCON" + data.defcon, "d"+data.defcon)
	    append(tr, "td", data.latency +"ns")
	    append(tr, "td", tsf(data.octets_ps*8) + "bps")
	    append(tr, "td", tsf(data.packets_ps) + "pps")
	    append(tr, "td", tsf(data.flows_ps) + " flows/s")
	    append(tr, "td", spc(data.concurrent))

	    
	    document.getElementById("summary").replaceWith(summary);
	    summary.id = "summary";
	    
	    
	    var rhi = document.createElement("div");
	    var t = append(rhi, "table")
	    for(var vip in data.rhi) {
		var tr = append(t, "tr", null, data.rhi[vip] ? "up" : "dn")
		append(tr, "td", `<a href="#`+vip+`">`+vip+`</a>`)
		append(tr, "td", dhms(data.when[vip]) + " " + (data.rhi[vip] ? "UP" : "DOWN"))
	    }
	    document.getElementById("rhi").replaceWith(rhi);
	    rhi.id = "rhi";

	    
	    var services = document.createElement("div");
	    	    
	    for(var vip in data.vips) {
		append(services, "div", "&nbsp;")
		append(services, "div", "&nbsp;")
		//append(services, "div", vip).setAttribute("id", vip)

		var t = append(services, "table")
		var tr = append(t, "tr")
		var td = append(tr, "td", vip, "ip")
		var td = append(tr, "td", dhms(data.when[vip]) + " " + (data.rhi[vip] ? "UP" : "DOWN"), data.rhi[vip] ? "up" : "dn" )		
		t.setAttribute("id", vip)
		
		append(services, "div", "&nbsp;")
		
		for(var l4 in data.vips[vip]) {
		    var s = service(vip, l4, data.vips[vip][l4])
		    services.appendChild(s)
		    append(services, "div", "&nbsp;")
		}
	    }
	    
	    document.getElementById("services").replaceWith(services);
	    services.id = "services";
	    
	}
    });
}

function dhms(s) {
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

function service(vip, l4, s) {
    var d = document.createElement("div")
    var t = append(d, "table")


    var m = append(t, "tr", null, "hd")
    append(m, "th", esc(s.name))
    var title = esc(s.description) + " [" + s.healthy + "/" +s.servers + " healthy, " + s.minimum + " needed]"
    append(m, "th", title).setAttribute("colspan", 4)
    append(m, "th", `<div title="Estimated concurrent connections">Concurrent*</div>`)
    
    var up = s.up ? "UP" : "DOWN"
    var udf = s.up ? "up" : "dn"
    
    if(s.fallback_on)  {
	up = "FALLBACK"
	udf = "fb"
    }

    
    var tr = append(t, "tr", null, udf)
    append(tr, "th", vip)
    append(tr, "th", l4)
    //append(tr, "th", up)
    append(tr, "th", dhms(s.when) + " " + up)
    append(tr, "th", tsf(s.octets_ps*8) + "bps")
    append(tr, "th", tsf(s.packets_ps) + "pps")
    append(tr, "th", spc(s.concurrent), "ar")
    
    for(var rip in s.rips) {
	var r = s.rips[rip]
	var tr = append(t, "tr", null, r.up ? "up" : "dn")
	var when = dhms(r.when)

	var span = document.createElement("span")
	span.setAttribute("title", r.message)
	span.innerHTML = when + " " + (r.up ? "UP" : "DOWN") + " ("+r.duration_ms+"ms)"
	
	
	append(tr, "td", rip)
	append(tr, "td", r.mac)
	//append(tr, "td", when + " " + (r.up ? "UP" : "DOWN") + " ("+r.duration_ms+"ms)")

	var td = append(tr, "td")
	td.appendChild(span)
	
	append(tr, "td", spc(r.octets_ps*8), "ar")
	append(tr, "td", spc(r.packets_ps), "ar")
	append(tr, "td", spc(r.concurrent), "ar")
    }

    if(s.fallback) {
	var tr = append(t, "tr", null, s.fallback_up ? "up" : "dn")
	append(tr, "td", "Fallback")
	append(tr, "td", "localhost")
	append(tr, "td", s.fallback_up ? "UP" : "DOWN")
	append(tr, "td", "not")
	append(tr, "td", "tracked")
	append(tr, "td", "yet")
    }
    
    return d
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

function esc(s)
{
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


var lastms = 0;

function lb() {
    
    //var url = window.location.href + 'stats.json';
    var url = '/stats.json';
    var log = '/log/';    
    //var log = window.location.href + 'log/';    

    console.log(url)
    function refresh() {
	updateStats(url);
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

    getJSON(url+lastms, function(err, data) {
        if (err !== null) {
            //alert('Something went wrong: ' + err);
        } else {
            data.forEach(function(item, index) {
                //console.log(index);
                //if(item.Level < 7) {
                    lastms = item.Ms;
                    var date = new Date(lastms);
                    var time = date.toLocaleString();
                    addMessage(time + ": " + item.Text);
                //}
            })
        }
    })
}
