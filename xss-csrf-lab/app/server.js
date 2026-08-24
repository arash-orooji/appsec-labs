const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// شبیه‌سازی نشست کاربر
app.use((req, res, next) => {
  if (!req.cookies.session) {
    res.cookie('session', 'user-123-token', { httpOnly: false });
  }
  next();
});

// ---------- آسیب‌پذیری XSS (Reflected) ----------
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  // آسیب‌پذیر: ورودی بدون sanitize بازتاب داده می‌شود
  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${query}</p>
        <form action="/search" method="GET">
          <input name="q" placeholder="Search..." />
          <button type="submit">Search</button>
        </form>
      </body>
    </html>
  `);
});

// ---------- آسیب‌پذیری CSRF ----------
app.get('/profile', (req, res) => {
  res.send(`
    <html>
      <body>
        <h1>Update Email</h1>
        <!-- آسیب‌پذیر: بدون توکن CSRF -->
        <form action="/update-email" method="POST">
          <input name="email" placeholder="New email" />
          <button type="submit">Update</button>
        </form>
      </body>
    </html>
  `);
});

app.post('/update-email', (req, res) => {
  const email = req.body.email;
  // آسیب‌پذیر: بدون بررسی CSRF token یا Origin/Referer
  res.send(`<h1>Email updated to: ${email}</h1>`);
});

app.get('/', (req, res) => {
  res.send(`
    <html><body>
      <h1>XSS & CSRF Lab</h1>
      <ul>
        <li><a href="/search?q=test">XSS Lab (Search)</a></li>
        <li><a href="/profile">CSRF Lab (Profile)</a></li>
      </ul>
    </body></html>
  `);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vulnerable app running on port ${PORT}`);
});
