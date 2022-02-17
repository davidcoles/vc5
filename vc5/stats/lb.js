var currents = {};
var lastms = 0;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function addMessage(msg) {
    var consoleElement = document.querySelectorAll('#console')[0];
    var messageElement = document.createElement('div');
    messageElement.innerHTML = msg;
    if(consoleElement.childElementCount > 1000 ) {
        consoleElement.removeChild(consoleElement.lastChild);
    }
    consoleElement.insertBefore(messageElement, consoleElement.firstChild);
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

function calculatePoint(i, intervalSize, colorRangeInfo) {
    var { colorStart, colorEnd, useEndAsStart } = colorRangeInfo;
    return (useEndAsStart
	    ? (colorEnd - (i * intervalSize))
	    : (colorStart + (i * intervalSize)));
}

function interpolateColors(dataLength, colorScale, colorRangeInfo) {
    var { colorStart, colorEnd } = colorRangeInfo;
    var colorRange = colorEnd - colorStart;
    var intervalSize = colorRange / dataLength;
    var i, colorPoint;
    var colorArray = [];
    
    for (i = 0; i < dataLength; i++) {
	colorPoint = calculatePoint(i, intervalSize, colorRangeInfo);
	colorArray.push(colorScale(colorPoint));
    }
    
    return colorArray;
}  

function piechart (title, xvals, yvals) {
    var xValues = xvals;
    var yValues = yvals;

    const colorScale = d3.interpolateRainbow;
    
    const colorRangeInfo = {
	colorStart: 0,
	colorEnd: 1,
	useEndAsStart: false,
    }; 

    var colors = interpolateColors(xvals.length, colorScale, colorRangeInfo);

    new Chart("doughnut", {
	type: "doughnut",
	data: {
	    labels: xvals,
	    datasets: [{
		backgroundColor: colors,
		data: yvals
	    }]
	},
	options: {
	    animation: {
		duration: 0
	    },
	    title: {
		display: true,
		text: title
	    },
	}
    });	
}


function linechart(title, xvals, yvals) {

    new Chart("line", {
	type: "line",
	data: {
	    labels: xvals,
	    datasets: [{
		fill: false,
		lineTension: 0,
		backgroundColor: "rgba(0,0,255,1.0)",
		borderColor: "rgba(0,0,255,0.1)",
		data: yvals
	    }]
	},
	options: {
	    responsive: false,
	    animation: {
	        duration: 0
	    },
	    legend: {display: false}
	}
	
    });
    
}

function updateStats(url) {
    


    getJSON(url, function(err, data) {	
	if (err !== null) {
	    alert('Something went wrong: ' + err);
	} else {
	    //alert('Your query count: ' + data.query.count);
	    //console.log(data);
	    
	    var dl = document.getElementById("list");
	    var services = document.getElementById("services");
	    var rhi = document.getElementById("rhi");
	    var global = document.getElementById("global");


	    //"average_latency_ns": 850,
	    //"packets_per_second": 280,
	    //"total_connections": 13,
	    //"rx_packets": 2133351,
	    //"rx_octets": 163047398,
	    //"userland_queue_failed": 0,

	    //piechart();

	    var connections = {};
	    var current = 0;
	    
	    global.innerHTML = data.average_latency_ns + "ns latency, " + data.packets_per_second + "pps, " + data.rx_octets + " rx_octets, " + data.rx_packets + " rx_packets, " + data.total_connections + " total_connections, " + data.current_connections + " current_connections";
	    
	    for(var i in data.route_health_injection) {
		var up = data.route_health_injection[i];
		var ip = document.getElementById(i);
                if(!ip) {
                    ip = document.createElement("div");
		    ip.id = i;
		    ip.style = "line-height: 1.5em;";
		    rhi.appendChild(ip);
		}

		ip.innerHTML = i + ": " + (up ? "up" : "down");
	    }

	    var newdiv = document.createElement("div");

	    services.replaceWith(newdiv);

	    newdiv.id = "services";
	    
	    for(var s in data.services) {
		//console.log(s);

		var sv =  data.services[s];
		
		var sd = document.getElementById(s);
		if(!sd) {
		    sd = document.createElement("div");
		    sd.id = s;
		    sd.style = "line-height: 2em;";
		    //services.appendChild(sd);
		    newdiv.appendChild(sd);
		    
		}

		var ih = s + ": " + sv.name + " (" + sv.description + ")";

		ih += ", " + (sv.up ? "up" : "down") + ", " + sv.rx_octets + " rx_octets, " +  sv.rx_packets + " rx_packets, "+ sv.total_connections + " total_connections, " + sv.current_connections + " current_connections";

		
		sd.innerHTML = ih;
		
		
		
		var be = data.services[s].backends;
		
		for(var b in be) {
		    //console.log(b);
		    //console.log(data.services[s].backends[b]);
		    
		    var bh = data.services[s].backends[b];
		    
		    var id = s + "/" + b;
		    
		    var bd = document.getElementById(id);
		    if(!bd) {
			bd = document.createElement("div");
			bd.id = id;
			bd.style = "padding-left: 50px; line-height: 1.5em;";
			sd.appendChild(bd);
		    }
		    bd.innerHTML = b + " [" + bh.mac + "]"  + ": " + (bh.up ? "up" : "down") + ", " + bh.rx_octets + " rx_octets, " +  bh.rx_packets + " rx_packets, " + bh.total_connections + " total_connections, " + bh.current_connections + " current_connections";

		    if(!connections[b]) {
			connections[b] = 0;
		    }
		    connections[b] += bh.current_connections;
		    current += bh.current_connections;
		    
		}    
		
	    };

	    var xvals = [];
	    var yvals = [];

	    for(var c in connections) {
		xvals.push(c);
		yvals.push(connections[c]);
	    }
	    //console.log(yvals);

	    piechart("backend connections", xvals, yvals);


	    var nowd10 = Math.floor(Date.now() / 10000)

	    if(!currents[nowd10]) {
		currents[nowd10] = current;
	    }

	    var cks = Object.keys(currents);
	    cks.sort(function(a, b) {
		return a - b;
	    });
	    //while(cks.length > 10) {
	    //    var d = cks.shift;
	    //    delete currents[d];
	    //}

	    if(cks.length > 100) {
		var d = cks.shift();
		delete currents[d];
	    }
	    xvals = [];
	    yvals = [];

	    cks.forEach(function(item, index) {
		xvals.push(item);
		yvals.push(currents[item]);
	    });

	    //linechart("current connections", xvals, yvals);
	}
    });

}

function updateLogs(url) {
    
    getJSON(url+lastms, function(err, data) {	
	if (err !== null) {
	    alert('Something went wrong: ' + err);
	} else {
            data.forEach(function(item, index) {
		//console.log(index);
		if(item.Level < 6) {
		    lastms = item.Ms;
		    var date = new Date(lastms);
		    var time = date.toLocaleString();
		    addMessage(time + ": " + item.Entry.join(" "));
		}		
	    })
	}
    })
}


function lb() {
    
    var url = window.location.href + 'stats/';
    var log = window.location.href + 'log/';    

    function doevent() {
	updateStats(url);
	updateLogs(log);	
	setTimeout(doevent, 3000);
    }

    setTimeout(doevent, 100);
}

function getParameterByName(name, url = window.location.href) {
    name = name.replace(/[\[\]]/g, '\\$&');
    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

window.lb = lb;
window.getParameterByName = getParameterByName;
