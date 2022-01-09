Authorization: Basic '...'

'...' -> base64('username:password') -> encoded

BasicAuthnFilter -> Authorization: Basic (username:password)
TokenAuthnFilter -> X-Token: ...

authnManager.authentication(new TokenAuthentication(token, null))
authnManager.authentication(new UsernamePasswordAuthentication(username, password))

getCookies
