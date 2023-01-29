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
	    alert('Something went wrong: ' + err);
	} else {
	    
	    var summary = document.createElement("div");
	    summary.innerHTML = "DEFCON" + data.defcon + " " + data.latency +"ns " +
		tsf(data.octets_ps*8) + "bps " + tsf(data.packets_ps) + "pps "+ tsf(data.flows_ps) + " flows/s "

	    document.getElementById("summary").replaceWith(summary);
	    summary.id = "summary";
	    
	    
	    var rhi = document.createElement("div");
	    for(var vip in data.rhi) {
		var v = document.createElement("div");
		v.innerHTML = vip + ": " + (data.rhi[vip] ? "UP" : "DOWN")
		rhi.appendChild(v)
	    }
	    document.getElementById("rhi").replaceWith(rhi);
	    rhi.id = "rhi";

	    
	    var services = document.createElement("div");
	    	    
	    for(var vip in data.vips) {
		for(var l4 in data.vips[vip]) {
		    var service =  data.vips[vip][l4]
		    var n = document.createElement("div")
		    var up = service.up ? "UP" : "DOWN"
		    if(service.fallback)  {
			up = "FALLBACK"
		    }
		    
		    n.innerHTML = vip + ":" + l4 + " " + up + " " +
			tsf(service.octets_ps*8) + "bps " + tsf(service.packets_ps) + "pps " + service.concurrent + " active conns " +
			" - " + service.name + " - " + service.description
		    
		    services.appendChild(n)
		    
		    var rips = service.rips
		    for(var rip in rips) {
			var n = document.createElement("div");
			var r = rips[rip]
			n.innerHTML = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" +
			    rip + " " + (r.up ? "UP" : "DOWN") + " " +
			     tsf(r.octets_ps*8) + "bps " + tsf(r.packets_ps) + "pps " + r.concurrent + " active conns "
			    
			services.appendChild(n)
		    }
		}
	    }
	    
	    document.getElementById("services").replaceWith(services);
	    services.id = "services";
	    
	}
    });

}


function lb() {
    
    var url = window.location.href + 'stats.json';
    //var log = window.location.href + 'log/';    

    console.log(url)
    function doevent() {
	updateStats(url);
	setTimeout(doevent, 1000);
    }

    setTimeout(doevent, 100);
}

window.lb = lb;

