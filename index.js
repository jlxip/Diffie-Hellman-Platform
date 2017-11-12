const http = require('http')
const url = require('url')
const crypto = require('crypto')

function parseCookies(request) {
	var list = {}
	rc = request.headers.cookie
	rc && rc.split(';').forEach(function(cookie) {
		var parts = cookie.split('=')
		list[parts.shift().trim()] = decodeURI(parts.join('='))
	})
	return list
}

http.createServer((req, res) => {
	const params = url.parse(req.url, true).query
	var host = ''
	if(req.connection.encrypted) host = 'https://'
	else host = 'http://'
	host += req.headers.host;
	const encodeType = 'base64'

	if('g' in params && 'r' in params) {
		var DH = crypto.createDiffieHellman(params.g, encodeType)
		var cookies = parseCookies(req)
		if('x' in cookies) {
			try {
				var privKey = decodeURIComponent(parseCookies(req).x)
				DH.setPrivateKey(privKey, encodeType)
				var secret = DH.computeSecret(decodeURIComponent(params.r), encodeType)

				res.writeHead(200, {'Content-Type': 'text/html', 'Set-Cookie': 'x=deleted; expires=Thu, 01 Jan 1970 00:00:00 GTM'})
				res.write('The secret is: '+secret.toString('base64'))
			} catch(e) {
				res.writeHead(200, {'Content-Type': 'text/html'})
				res.write('Something went really wrong. Try loading the previous URL.')
			}
		} else {
			res.writeHead(200, {'Content-Type': 'text/html'})
			res.write('You don\'t have the \'x\' (private key) cookie.')
		}
	} else if('g' in params) {
		res.writeHead(200, {'Content-Type': 'text/html', 'Set-Cookie': 'x='+x})

		try {
			var DH = crypto.createDiffieHellman(decodeURIComponent(params.g), encodeType)
			var r = encodeURIComponent(DH.generateKeys(encodeType))
			var x = encodeURIComponent(DH.getPrivateKey(encodeType))

			res.write('Don\'t access. Just share:<br>\n'+host+'/?g='+encodeURIComponent(params.g)+'&r='+r)
		} catch(e) {
			res.write('The generator (\'g\' by GET) is not valid.')
		}
	} else if('s' in params) {
		res.writeHead(200, {'Content-Type': 'text/html'})
		if(parseInt(params.s)) {
			var newDH = crypto.createDiffieHellman(parseInt(params.s))
			var g = encodeURIComponent(newDH.getPrime(encodeType))

			res.write('Share and access:<br>\n'+host+'/?g='+g)
		} else {
			res.write('Wrong size. Choose a power of two. 512 for tests. 2048 for real scenarios (it might be slower to generate).')
		}
	} else {
		res.writeHead(200, {'Content-Type': 'text/html'})
		res.write('First, create a G value:<br>\n'+host+'/?s=2048')
	}

	res.end()
}).listen(9234)