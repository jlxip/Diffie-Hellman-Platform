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
	var params = url.parse(req.url, true).query
	const encodeType = 'base64'

	if('g' in params && 'r' in params) {
		var DH = crypto.createDiffieHellman(params.g, encodeType)
		var cookies = parseCookies(req)
		if('x' in cookies) {
			var privKey = decodeURIComponent(parseCookies(req).x)
			DH.setPrivateKey(privKey, encodeType)
			var secret = DH.computeSecret(decodeURIComponent(params.r), encodeType)

			res.writeHead(200, {'Content-Type': 'text/html', 'Set-Cookie': 'x=deleted; expires=Thu, 01 Jan 1970 00:00:00 GTM'})
			res.write('The secret is: '+secret.toString('base64'))
		} else {
			res.writeHead(200, {'Content-Type': 'text/html'})
			res.write('You don\'t have the \'x\' (private key) cookie.')
		}
	} else if('g' in params) {
		var DH = crypto.createDiffieHellman(decodeURIComponent(params.g), encodeType)
		var r = encodeURIComponent(DH.generateKeys(encodeType))
		var x = encodeURIComponent(DH.getPrivateKey(encodeType))

		res.writeHead(200, {'Content-Type': 'text/html', 'Set-Cookie': 'x='+x})
		res.write('Don\'t access. Just share:<br>\nhttps://dh.jlxip.net/?g='+encodeURIComponent(params.g)+'&r='+r)
	} else if('s' in params) {
		var newDH = crypto.createDiffieHellman(parseInt(params.s))
		var g = encodeURIComponent(newDH.getPrime(encodeType))

		res.writeHead(200, {'Content-Type': 'text/html'})
		res.write('Share and access:<br>\nhttps://dh.jlxip.net/?g='+g)
	} else {
		res.writeHead(200, {'Content-Type': 'text/html'})
		res.write('First, create a G value:<br>\nhttps://dh.jlxip.net/?s=2048')
	}

	res.end()
}).listen(9234)