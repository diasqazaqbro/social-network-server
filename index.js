import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { promisify } from 'node:util'
import express from 'express'

const PORT = 3001
const WEEK = 7 * 24 * 60 * 60 * 1000
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const USERNAME = /^[a-zA-Z0-9._]{1,30}$/
const USER_FIELDS = 'users.id, username, email, full_name AS fullName'
const scryptAsync = promisify(scrypt)

const db = new DatabaseSync(`${import.meta.dirname}/db.sqlite`)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
  );
`)

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex')
  return `${salt}:${(await scryptAsync(password, salt, 64)).toString('hex')}`
}

async function checkPassword(password, stored) {
  const [salt, hash] = stored.split(':')
  return timingSafeEqual(await scryptAsync(password, salt, 64), Buffer.from(hash, 'hex'))
}

// Демо-аккаунт, чтобы можно было войти сразу после первого запуска
if (!db.prepare('SELECT 1 FROM users').get()) {
  db.prepare('INSERT INTO users (username, email, full_name, password_hash) VALUES (?, ?, ?, ?)')
    .run('diasqazaqbro', 'dias@example.com', 'Adil Dias | Кудрявый программист', await hashPassword('123456'))
}

/** Сессия хранится в БД, в cookie только случайный токен. */
function startSession(res, userId) {
  const token = randomBytes(32).toString('hex')
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(token, userId, Date.now() + WEEK)
  res.cookie('sid', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: WEEK,
  })
}

const readSid = (req) => req.get('cookie')?.match(/(?:^|;\s*)sid=([0-9a-f]+)/)?.[1] ?? ''
const str = (value) => (typeof value === 'string' ? value : '')

const app = express()
app.use(express.json())

app.get('/api/me', (req, res) => {
  const user = db.prepare(`
    SELECT ${USER_FIELDS} FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE token = ? AND expires_at > ?
  `).get(readSid(req), Date.now())
  if (!user) return res.status(401).json({ error: 'Вы не вошли в аккаунт.' })
  res.json(user)
})

app.post('/api/login', async (req, res) => {
  const login = str(req.body?.login).trim()
  const password = str(req.body?.password)
  if (!login || !password) return res.status(400).json({ error: 'Заполните все поля.' })

  const user = db.prepare(`SELECT ${USER_FIELDS}, password_hash FROM users WHERE username = ? OR email = ?`)
    .get(login, login)
  if (!user || !(await checkPassword(password, user.password_hash))) {
    return res.status(401).json({ error: 'Неверное имя пользователя или пароль. Проверьте данные и повторите попытку.' })
  }

  delete user.password_hash
  startSession(res, user.id)
  res.json(user)
})

app.post('/api/register', async (req, res) => {
  const email = str(req.body?.email).trim()
  const fullName = str(req.body?.fullName).trim()
  const username = str(req.body?.username).trim()
  const password = str(req.body?.password)

  const error =
    (!EMAIL.test(email) && 'Введите корректный электронный адрес.') ||
    ((!fullName || fullName.length > 64) && 'Укажите имя и фамилию (до 64 символов).') ||
    (!USERNAME.test(username) && 'Имя пользователя: до 30 символов, только латинские буквы, цифры, точки и подчёркивания.') ||
    ((password.length < 6 || password.length > 128) && 'Пароль должен содержать от 6 до 128 символов.')
  if (error) return res.status(400).json({ error })

  let id
  try {
    id = db.prepare('INSERT INTO users (username, email, full_name, password_hash) VALUES (?, ?, ?, ?)')
      .run(username, email, fullName, await hashPassword(password)).lastInsertRowid
  } catch (err) {
    if (!err.message.includes('UNIQUE')) throw err
    return res.status(409).json({
      error: err.message.includes('users.email')
        ? 'Этот электронный адрес уже используется.'
        : 'Это имя пользователя уже занято.',
    })
  }

  startSession(res, id)
  res.status(201).json({ id, username, email, fullName })
})

app.post('/api/logout', (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(readSid(req))
  res.clearCookie('sid').sendStatus(204)
})

app.listen(PORT, () => console.log(`API: http://localhost:${PORT}`))
