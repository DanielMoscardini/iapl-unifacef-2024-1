import Cryptr from 'cryptr'
import prisma from '../database/client.js'

export default async function(req, res, next) {

  const bypassRoutes = [
    { url: '/users/login', method: 'POST' },
    { url: '/users', method: 'POST' }
  ]

  for(let route of bypassRoutes) {
    if(route.url === req.url && route.method === req.method) {
      console.log(`Rota ${route.url}, método ${route.method} não autenticados por exceção`)
      next()
      return
    }
  }

  let cryptoSessid = null

  cryptoSessid = req.cookies[process.env.AUTH_COOKIE_NAME]

  if(! cryptoSessid) {
    const authHeader = req.headers['authorization']
    if(! authHeader) {
      console.error('ERRO: não autenticado por falta de cookie ou cabeçalho de autorização')
      return res.status(403).end()
    }
  
    const [ , _token] = authHeader.split(' ')
    cryptoSessid = _token
  }

  let sessid
  
  try {
    // const cryptr = new Cryptr(process.env.TOKEN_SECRET)
    // sessid = cryptr.decrypt(cryptoSessid)
    sessid = cryptoSessid
  }
  catch {
    console.error('ERRO: não autenticado por falha na decodificação da sessid')
    return res.status(403).end()
  }

  let session
  try {
    session = await prisma.session.findUniqueOrThrow({
      where: { sessid },
      include: { user: true }
    })
  }
  catch {
    console.error('ERRO: não autenticado por erro na recuperação das informações da sessão')
    return res.status(403).end()
  }

  const now = new Date()
  if(now.getTime() - session.start_time.getTime() > Number(process.env.SESSION_DURATION)) {
    console.error('ERRO: não autenticado por sessão expirada.')
    return res.status(403).end()
  }

  if(session.user?.password) delete session.user?.password
  req.authUser = session.user

  next()
}
