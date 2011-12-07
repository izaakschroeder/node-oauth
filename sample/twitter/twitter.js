
var 
	OAuth = require('oauth/1'), 
	Presto = require('presto'), 
	https = require('https'), 
	querystring = require('querystring');

var config = require('./config');
config.endpoint = config.endpoint || "https://api.twitter.com/oauth";

var oauth = new OAuth(config);
var app = new Presto({
	port: 5555
})

app.route("^/$", function(env) {
	env.response.writeHead(200, { "Content-Type": "text/html" });
	env.response.end('<html><body><a href="/authenticate/twitter">Log In</a></body></html>');
});

app.route("^/authenticate/twitter$", function(env) {
	oauth.requestToken({ callback: "http://10.0.1.3:5555/oauth/1.0a/callback" }, function(token) {
		if (token) {
			env.response.writeHead(302, { Location: oauth.authenticateURL(token) });
			env.response.end("You are now being redirected.");
		}
		else {
			env.response.writeHead(500);
			env.response.end("Something went wrong getting the token!");
		}
	})
})

app.route("^/oauth/1.0a/callback$", function(env) {
	oauth.accessToken(env.request, function(token) {
		if (token) {
			var request = https.request({
				host: "api.twitter.com",
				port: 443,
				path: "/1/statuses/update.json",
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				}
			}, function(response) {
				if (response.statusCode >= 200 && response.statusCode < 300) {
					env.response.end("Updated your Twitter feed for you!");
				}
				else {
					env.response.end("Failed to updated your Twitter feed for you (got "+response.statusCode+")!");
				}
			});
			
			oauth.authorize(request, token);
			request.end(querystring.stringify({
				status: "Hello World"
			}));
		}
		else {
			env.response.end("Failed to acquire access token!");
		}
	})
})

app.run();
