const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kif-wallet-secret-2024';

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Base de dados
const db = new Database('./kif.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    nome TEXT NOT NULL,
    telefone TEXT UNIQUE NOT NULL,
    pin TEXT NOT NULL,
    saldo REAL DEFAULT 0,
    codigo_afiliado TEXT UNIQUE,
    afiliado_por TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transacoes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tipo TEXT NOT NULL,
    valor REAL NOT NULL,
    descricao TEXT,
    referencia TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS kixikilas (
    id TEXT PRIMARY KEY,
    nome TEXT NOT NULL,
    criador_id TEXT NOT NULL,
    valor_mensal REAL NOT NULL,
    total_membros INTEGER NOT NULL,
    membros_actuais INTEGER DEFAULT 1,
    estado TEXT DEFAULT 'aberta',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS kixikila_membros (
    id TEXT PRIMARY KEY,
    kixikila_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    posicao INTEGER,
    pago INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS agentes (
    id TEXT PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    comissao_total REAL DEFAULT 0,
    nivel TEXT DEFAULT 'basico',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tokens_blacklist (
    token TEXT PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed admin
const adminExiste = db.prepare('SELECT id FROM users WHERE telefone = ?').get('923000001');
if (!adminExiste) {
  db.prepare('INSERT INTO users (id, nome, telefone, pin, saldo, codigo_afiliado) VALUES (?, ?, ?, ?, ?, ?)')
    .run(uuidv4(), 'Admin KiF', '923000001', bcrypt.hashSync('1234', 10), 100000, 'KIF-FORTUNA');
}

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token necessário' });
  const blacklisted = db.prepare('SELECT token FROM tokens_blacklist WHERE token = ?').get(token);
  if (blacklisted) return res.status(401).json({ erro: 'Sessão expirada' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido' });
  }
}

// ==================== ROTAS ====================

// Registo
app.post('/api/registar', (req, res) => {
  const { nome, telefone, pin, codigo_afiliado } = req.body;
  if (!nome || !telefone || !pin) return res.status(400).json({ erro: 'Dados incompletos' });
  const existe = db.prepare('SELECT id FROM users WHERE telefone = ?').get(telefone);
  if (existe) return res.status(400).json({ erro: 'Telefone já registado' });
  const id = uuidv4();
  const pinHash = bcrypt.hashSync(pin, 10);
  const codigoAfiliado = 'KIF-' + telefone.slice(-6);
  let afiliado_por = null;
  if (codigo_afiliado) {
    const ref = db.prepare('SELECT id FROM users WHERE codigo_afiliado = ?').get(codigo_afiliado);
    if (ref) {
      afiliado_por = ref.id;
      db.prepare('UPDATE users SET saldo = saldo + 500 WHERE id = ?').run(ref.id);
      db.prepare('INSERT INTO transacoes (id, user_id, tipo, valor, descricao) VALUES (?, ?, ?, ?, ?)')
        .run(uuidv4(), ref.id, 'bonus_referral', 500, 'Bónus de referral');
    }
  }
  db.prepare('INSERT INTO users (id, nome, telefone, pin, codigo_afiliado, afiliado_por) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, nome, telefone, pinHash, codigoAfiliado, afiliado_por);
  res.json({ mensagem: 'Conta criada com sucesso', codigo_afiliado: codigoAfiliado });
});

// Login
app.post('/api/login', (req, res) => {
  const { telefone, pin } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE telefone = ?').get(telefone);
  if (!user || !bcrypt.compareSync(pin, user.pin)) return res.status(401).json({ erro: 'Credenciais inválidas' });
  const token = jwt.sign({ id: user.id, telefone: user.telefone }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, nome: user.nome, saldo: user.saldo });
});

// Logout
app.post('/api/logout', auth, (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  db.prepare('INSERT OR IGNORE INTO tokens_blacklist (token) VALUES (?)').run(token);
  res.json({ mensagem: 'Sessão terminada' });
});

// Dashboard
app.get('/api/dashboard', auth, (req, res) => {
  const user = db.prepare('SELECT id, nome, telefone, saldo, codigo_afiliado FROM users WHERE id = ?').get(req.user.id);
  const transacoes = db.prepare('SELECT * FROM transacoes WHERE user_id = ? ORDER BY created_at DESC LIMIT 10').all(req.user.id);
  res.json({ ...user, transacoes });
});

// Depósito
app.post('/api/depositar', auth, (req, res) => {
  const { valor } = req.body;
  if (!valor || valor <= 0) return res.status(400).json({ erro: 'Valor inválido' });
  db.prepare('UPDATE users SET saldo = saldo + ? WHERE id = ?').run(valor, req.user.id);
  db.prepare('INSERT INTO transacoes (id, user_id, tipo, valor, descricao) VALUES (?, ?, ?, ?, ?)')
    .run(uuidv4(), req.user.id, 'deposito', valor, 'Depósito');
  const user = db.prepare('SELECT saldo FROM users WHERE id = ?').get(req.user.id);
  res.json({ mensagem: 'Depósito realizado', saldo: user.saldo });
});

// Levantamento
app.post('/api/levantar', auth, (req, res) => {
  const { valor, pin } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(pin, user.pin)) return res.status(401).json({ erro: 'PIN incorreto' });
  if (valor <= 0 || valor > user.saldo) return res.status(400).json({ erro: 'Saldo insuficiente' });
  const hoje = new Date().toISOString().split('T')[0];
  const levantadoHoje = db.prepare(`SELECT COALESCE(SUM(valor),0) as total FROM transacoes WHERE user_id = ? AND tipo = 'levantamento' AND date(created_at) = ?`).get(req.user.id, hoje);
  if (levantadoHoje.total + valor > 500000) return res.status(400).json({ erro: 'Limite diário de 500.000 Kz atingido' });
  db.prepare('UPDATE users SET saldo = saldo - ? WHERE id = ?').run(valor, req.user.id);
  db.prepare('INSERT INTO transacoes (id, user_id, tipo, valor, descricao) VALUES (?, ?, ?, ?, ?)')
    .run(uuidv4(), req.user.id, 'levantamento', valor, 'Levantamento');
  const updated = db.prepare('SELECT saldo FROM users WHERE id = ?').get(req.user.id);
  res.json({ mensagem: 'Levantamento realizado', saldo: updated.saldo });
});

// Transferência P2P
app.post('/api/transferir', auth, (req, res) => {
  const { telefone_destino, valor, pin } = req.body;
  const remetente = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(pin, remetente.pin)) return res.status(401).json({ erro: 'PIN incorreto' });
  const destinatario = db.prepare('SELECT * FROM users WHERE telefone = ?').get(telefone_destino);
  if (!destinatario) return res.status(404).json({ erro: 'Destinatário não encontrado' });
  if (remetente.id === destinatario.id) return res.status(400).json({ erro: 'Não podes transferir para ti mesmo' });
  if (valor <= 0 || valor > remetente.saldo) return res.status(400).json({ erro: 'Saldo insuficiente' });
  const comissao = valor * 0.02;
  const valorLiquido = valor - comissao;
  db.prepare('UPDATE users SET saldo = saldo - ? WHERE id = ?').run(valor, remetente.id);
  db.prepare('UPDATE users SET saldo = saldo + ? WHERE id = ?').run(valorLiquido, destinatario.id);
  db.prepare('INSERT INTO transacoes (id, user_id, tipo, valor, descricao, referencia) VALUES (?, ?, ?, ?, ?, ?)')
    .run(uuidv4(), remetente.id, 'transferencia_saida', valor, `Transferência para ${destinatario.nome}`, destinatario.telefone);
  db.prepare('INSERT INTO transacoes (id, user_id, tipo, valor, descricao, referencia) VALUES (?, ?, ?, ?, ?, ?)')
    .run(uuidv4(), destinatario.id, 'transferencia_entrada', valorLiquido, `Transferência de ${remetente.nome}`, remetente.telefone);
  const updated = db.prepare('SELECT saldo FROM users WHERE id = ?').get(remetente.id);
  res.json({ mensagem: 'Transferência realizada', saldo: updated.saldo });
});

// Top-up
app.post('/api/topup', auth, (req, res) => {
  const { telefone, operadora, valor, pin } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(pin, user.pin)) return res.status(401).json({ erro: 'PIN incorreto' });
  if (valor <= 0 || valor > user.saldo) return res.status(400).json({ erro: 'Saldo insuficiente' });
  const comissao = valor * 0.05;
  db.prepare('UPDATE users SET saldo = saldo - ? WHERE id = ?').run(valor, req.user.id);
  db.prepare('INSERT INTO transacoes (id, user_id, tipo, valor, descricao) VALUES (?, ?, ?, ?, ?)')
    .run(uuidv4(), req.user.id, 'topup', valor, `Top-up ${operadora} para ${telefone}`);
  const updated = db.prepare('SELECT saldo FROM users WHERE id = ?').get(req.user.id);
  res.json({ mensagem: `Top-up ${operadora} realizado para ${telefone}`, saldo: updated.saldo, comissao });
});

// Kixikila — criar
app.post('/api/kixikila/criar', auth, (req, res) => {
  const { nome, valor_mensal, total_membros } = req.body;
  if (!nome || !valor_mensal || !total_membros) return res.status(400).json({ erro: 'Dados incompletos' });
  const id = uuidv4();
  db.prepare('INSERT INTO kixikilas (id, nome, criador_id, valor_mensal, total_membros) VALUES (?, ?, ?, ?, ?)')
    .run(id, nome, req.user.id, valor_mensal, total_membros);
  db.prepare('INSERT INTO kixikila_membros (id, kixikila_id, user_id, posicao) VALUES (?, ?, ?, ?)')
    .run(uuidv4(), id, req.user.id, 1);
  res.json({ mensagem: 'Kixikila criada', id });
});

// Kixikila — aderir
app.post('/api/kixikila/aderir', auth, (req, res) => {
  const { kixikila_id } = req.body;
  const kixikila = db.prepare('SELECT * FROM kixikilas WHERE id = ?').get(kixikila_id);
  if (!kixikila) return res.status(404).json({ erro: 'Kixikila não encontrada' });
  if (kixikila.membros_actuais >= kixikila.total_membros) return res.status(400).json({ erro: 'Kixikila cheia' });
  const jaMembro = db.prepare('SELECT id FROM kixikila_membros WHERE kixikila_id = ? AND user_id = ?').get(kixikila_id, req.user.id);
  if (jaMembro) return res.status(400).json({ erro: 'Já és membro' });
  const posicao = kixikila.membros_actuais + 1;
  db.prepare('INSERT INTO kixikila_membros (id, kixikila_id, user_id, posicao) VALUES (?, ?, ?, ?)')
    .run(uuidv4(), kixikila_id, req.user.id, posicao);
  db.prepare('UPDATE kixikilas SET membros_actuais = membros_actuais + 1 WHERE id = ?').run(kixikila_id);
  res.json({ mensagem: 'Aderiste à Kixikila', posicao });
});

// Kixikila — listar
app.get('/api/kixikila/listar', auth, (req, res) => {
  const kixikilas = db.prepare('SELECT * FROM kixikilas WHERE estado = "aberta"').all();
  res.json(kixikilas);
});

// Agente — registar
app.post('/api/agente/registar', auth, (req, res) => {
  const jaAgente = db.prepare('SELECT id FROM agentes WHERE user_id = ?').get(req.user.id);
  if (jaAgente) return res.status(400).json({ erro: 'Já és agente' });
  db.prepare('INSERT INTO agentes (id, user_id) VALUES (?, ?)').run(uuidv4(), req.user.id);
  res.json({ mensagem: 'Registado como agente KiF' });
});

// Agente — dashboard
app.get('/api/agente/dashboard', auth, (req, res) => {
  const agente = db.prepare('SELECT * FROM agentes WHERE user_id = ?').get(req.user.id);
  if (!agente) return res.status(404).json({ erro: 'Não és agente' });
  const referidos = db.prepare('SELECT COUNT(*) as total FROM users WHERE afiliado_por = ?').get(req.user.id);
  res.json({ ...agente, total_referidos: referidos.total });
});

app.listen(PORT, () => console.log(`KiF Wallet rodando na porta ${PORT}`));
