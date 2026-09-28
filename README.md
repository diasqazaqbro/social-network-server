# social-network-server

Бэкенд входа для [social-network-client](https://github.com/diasqazaqbro/social-network-client): Express + SQLite (встроенный в Node `node:sqlite`).

## Запуск

Нужен Node 22+.

```bash
npm install
npm run dev   # http://localhost:3001, перезапускается при изменениях
```

База `db.sqlite` создаётся при первом запуске вместе с демо-аккаунтом: `diasqazaqbro` (или `dias@example.com`), пароль `123456`.

## Lab 3: GET + POST + cookie + validation

| Запрос | Что делает |
|---|---|
| `GET /api/me` | Возвращает пользователя по cookie `sid` или 401 |
| `POST /api/login` | Проверяет логин/email и пароль, ставит cookie `sid` |
| `POST /api/register` | Проверяет поля, создаёт пользователя, ставит cookie `sid` |
| `POST /api/logout` | Удаляет сессию из БД и cookie |

- Пароли хранятся как `scrypt`-хэш с солью.
- Cookie `sid` содержит только случайный токен (`HttpOnly`, `SameSite=Lax`), сама сессия лежит в таблице `sessions`.
- Проверка полей двойная: атрибуты формы в браузере и ещё раз на сервере.
