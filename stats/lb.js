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
	return Math.round(num).toString() + suffix[0];
    }

    if(num > 10) {
        return num.toFixed(1) + suffix[0];
    }
    
    return num.toFixed(2) + suffix[0];;
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
	    var defcon = document.getElementById("defcon");


	    var connections = {};
	    var current = 0;

	    switch(data.defcon) {
	    case 1:
		defcon.style.background = "white"
		break;
	    case 2:
		defcon.style.background = "#ff7373"
		break;
	    case 3:
		defcon.style.background = "#fdff73"
		break;
	    case 4:
		defcon.style.background = "#00d199"
		break;
	    case 5:
	    default:
		defcon.style.background ="#008dff"
	    }

	    defcon.innerHTML = "DEFCON " + data.defcon
	    
	    global.innerHTML = data.average_latency_ns + "ns latency, " + tsf(data.packets_per_second) + "pps, " + tsf(data.rx_octets) + " rx_octets, " + tsf(data.rx_packets) + " rx_packets, " + tsf(data.total_connections) + " total_connections, " + data.current_connections + " current_connections";
	    

	    var newrhi = document.createElement("div");
	    for(var i in data.route_health_injection) {
		var up = data.route_health_injection[i];
                var ip = document.createElement("div");
		ip.id = i;
		ip.style = "line-height: 1.5em;";
		ip.innerHTML = i + ": " + (up ? "up" : "down");
		newrhi.appendChild(ip);
	    }
	    newrhi.id = "rhi";	    
	    rhi.replaceWith(newrhi);


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

		ih += ", " + (sv.up ? "up" : "down") + ", " + tsf(sv.rx_octets) + " rx_octets, " +  tsf(sv.rx_packets) + " rx_packets, "+ tsf(sv.total_connections) + " total_connections, " + sv.current_connections + " current_connections";

		
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
		    bd.innerHTML = b + " [" + bh.mac + "]"  + ": " + (bh.up ? "up" : "down") + ", " + tsf(bh.rx_octets) + " rx_octets, " +  tsf(bh.rx_packets) + " rx_packets, " + tsf(bh.total_connections) + " total_connections, " + bh.current_connections + " current_connections";

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
