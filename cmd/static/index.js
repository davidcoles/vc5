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

	    var services = document.getElementById("services");
	    
	    var newdiv = document.createElement("div");

	    for(var s in data.vips) {
		for(var l in data.vips[s]) {
		    var n = document.createElement("div");
		    n.innerHTML = s + ":" + l
		    newdiv.appendChild(n)
		    for(var b in data.vips[s][l]) 
{			var n = document.createElement("div");
			var c = data.vips[s][l][b]
			n.innerHTML = "&nbsp;&nbsp;&nbsp;&nbsp;" + b + " " +
			tsf(c.octets) + "bytes " + tsf(c.packets) + "packets " +
			(c.up ? "UP" : "DOWN")
			newdiv.appendChild(n)
		    }
		}
	    }
	    
	    newdiv.id = "services";
	    services.replaceWith(newdiv);
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

