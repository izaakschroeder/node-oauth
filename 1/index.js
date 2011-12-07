
var 
	crypto = require('crypto'), 
	URL = require('url'), 
	querystring = require('querystring'), 
	https = require('https'),
	EventEmitter = require('events').EventEmitter,
	util = require('util');

/**
 *
 *
 *
 */
function OAuth(opts) {
	EventEmitter.call(this);
	this.consumerKey = opts.consumerKey;
	this.consumerSecret = opts.consumerSecret;
	this.endpoint = opts.endpoint;
	this.callback = opts.callback;
	var url = URL.parse(this.endpoint);
	this.path = url.pathname;
	this.host = url.host;
	this.secretTokenMap = { };
}
util.inherits(OAuth, EventEmitter);

/**
 *
 *
 *
 */
OAuth.encode = function(data) {
	return (''+data).replace(/[^A-Za-z0-9._~-]/g, function(input) {
		var strHex = input.charCodeAt(0).toString(16).toUpperCase(), out = "";
		if (strHex.length % 2 === 1)
			strHex = "0" + strHex;
		for (var i = 0; i < strHex.length; i+=2)
			out += "%" + strHex.substr(i, 2);
		return out;
			
	});
}

/**
 *
 *
 *
 */
OAuth.normalizeParameters = function(parameters) {
	var out = parameters;
	
	out.sort(function(a, b) {
		if (a.key > b.key)
			return 1;
		if (a.key < b.key)
			return -1;
		if (a.value > b.value)
			return 1;
		if (a.value < b.value)
			return -1;
		return 0;
	})

	
	var result = out.map(function(item){
		return OAuth.encode(item.key)+"="+OAuth.encode(item.value);
	}).join('&');

	return result;
}

/**
 *
 *
 *
 */
OAuth.baseString = function (request, auth, postParameters) {
	
	// http://tools.ietf.org/html/rfc5849#section-3.4.1
	var showPort = false;
	var hostHeader = request.getHeader("Host").match(/^([^:]+):?(.*)$/),
	host = hostHeader[1], port = parseInt(hostHeader[2]) || 443;

	var protocol = "https:";

	switch(protocol) {
	case "http:":
		showPort = port !== 80;
		break;
	case "https:":
		showPort = port !== 443;
		break;
	default:
		throw "Unknown protocol "+request.protocol;
	}

	var path = URL.parse(request.path, true);

	//If getHeader("Content-Type" === "application/x-www-form-urlencoded"
	var parameters = { }
	var baseString = protocol + "//" + host.toLowerCase() + (showPort ? ":"+port : "") + path.pathname;	
	var requestParameters = [ ];

	function processParameters(vals, noRealm) {
		for (var key in vals) {
			var value = vals[key];
			if (typeof value !== "undefined")
				if (!noRealm || key !== "realm")
					requestParameters.push({key: key, value: value});
		}
	}

	processParameters(auth, true);
	processParameters(postParameters || { });
	processParameters(path.query);

	return request.method + "&" + OAuth.encode(baseString) + "&" + OAuth.encode(OAuth.normalizeParameters(requestParameters));
};

/**
 *
 *
 *
 */
OAuth.prototype.authorize = function (request, cred, opts) {
	var oauth = this;
	cred = cred || { }
	opts = opts || { }


	function setAuthorizationHeader(postParameters) {
		// http://tools.ietf.org/html/rfc5849#section-3.4.2
		var 
			key = OAuth.encode(oauth.consumerSecret) + '&' + OAuth.encode(cred.tokenSecret || ''),
			hmac = crypto.createHmac('sha1', key);
		
		
		var auth = {
			oauth_signature_method: "HMAC-SHA1",
			oauth_consumer_key: oauth.consumerKey,
			oauth_token: cred.token,
			realm: cred.realm,
			oauth_timestamp:  Math.round(Date.now() / 1000),
			oauth_nonce: ('' + Math.round(Math.random() * 1e16) + Math.round(Math.random() * 1e16) + ''),
			oauth_callback: opts.callback || oauth.callback,
			oauth_version: "1.0"
		};

		baseString = OAuth.baseString(request, auth, postParameters)
		hmac.update(baseString);

		auth.oauth_signature = hmac.digest('base64')

		// http://tools.ietf.org/html/rfc5849#section-3.5.1
		var authorization = "OAuth " + Object.keys(auth).filter(function(k) {
			return typeof auth[k] !== "undefined";
		}).map(function (k) {
				return OAuth.encode(k) + '="' + OAuth.encode(auth[k]) + '"';
		}).join();

		request.setHeader("Authorization", authorization)
	}

	if (request.getHeader("Content-Type") === "application/x-www-form-urlencoded") {
		var oldEnd = request.end, oldWrite = request.write;

		request.oauthDataBuffer = "";

		request.write = function(data) {
			this.oauthDataBuffer += data;
		}

		request.end = function(data) {
			this.oauthDataBuffer += data;
			var postParameters = querystring.parse(data);
			setAuthorizationHeader(postParameters);
			oldWrite.call(this, this.oauthDataBuffer);
			oldEnd.call(this);
		}
	}
	else {
		setAuthorizationHeader();
	}
	
}

/**
 *
 *
 *
 */
OAuth.prototype.requestToken = function(opts, callback) {
	if (arguments.length === 1) {
		callback = opts;
		opts = { };
	}
	var oauth = this, request = https.request({
		host: this.host,
		path: this.path + "/request_token",
		port: 443,
		method: "POST"
	}, function(response) {
		if (response.statusCode >= 200 && response.statusCode < 300) {
			var buffer = "";
			response.on("data", function(data) {
				buffer += data;
			}).on("end", function(){
				var out = querystring.parse(buffer);
				if (out && out.oauth_callback_confirmed) {
					oauth.secretTokenMap[out.oauth_token] = out.oauth_token_secret;
					callback({
						token: out.oauth_token,
						tokenSecret: out.oauth_token_secret
					})
				}
				else {
					callback(null);
				}
			})
		}
		else {
			callback(null);
		}
	});
	this.authorize(request, opts);
	request.end();
}

/**
 *
 *
 *
 */
OAuth.prototype.accessToken = function(response, callback) {
	var oauth = this, buffer = "";
	var url = URL.parse(response.url, true);
	var
		data = querystring.parse(buffer),
		token = url.query.oauth_token, 
		verifier = url.query.oauth_verifier,
		tokenSecret = oauth.secretTokenMap[data.oauth_token];

	var request = https.request({
		host: oauth.host,
		path: oauth.path + "/access_token",
		port: 443,
		method: "POST"
	}, function(response) {
		if (response.statusCode >= 200 && response.statusCode < 300) {
			var buffer = "";
			response.on("data", function(data) {
				buffer += data;
			}).on("end", function(){
				var out = querystring.parse(buffer);
				callback({
					token: out.oauth_token,
					tokenSecret: out.oauth_token_secret
				})
			})
			
		}
		else {
			callback(null)
		}
	});
	oauth.authorize(request, {
		verifier: verifier,
		token: token,
		tokenSecret: tokenSecret
	});
	request.end();

	
}

/**
 *
 *
 *
 */
OAuth.prototype.authenticateURL = function(data) {
	return this.endpoint+"/authenticate?" + querystring.stringify({
			oauth_token: data.token
	})
}


module.exports = OAuth;