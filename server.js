const express = require('express');
const session = require('express-session');
const fs = require('fs').promises;
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const RADIOS_FILE = path.join(DATA_DIR, 'radios.json');
const PLAYLIST_FILE = path.join(DATA_DIR, 'playlist_history.json');
const AUTO_ASSIGN_INTERVAL_MS = parseInt(process.env.AUTO_ASSIGN_INTERVAL_MS || '6000'); // 6 sec default
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// JSON para API pública y URL-encoded para formularios
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// CORS abierto para API
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Sesiones para el panel web
app.use(session({
  secret: 'revdata-secret',
  resave: false,
  saveUninitialized: false
}));

app.use((req, res, next) => {
  res.locals.me = req.session.user || null;
  res.locals.active = '';
  next();
});

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}
async function readUsers() {
  try {
    const raw = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
async function saveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}
async function readPlaylistMaster() {
  try {
    const raw = await fs.readFile(PLAYLIST_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
function normalize(s){ return (s||'').toString().trim(); }
function normalizeArtist(a){ return (a||'').toString().trim().toUpperCase(); }

// Password helpers
// aceptar $2a, $2b, $2x, $2y
function isBcryptHash(str){
  return typeof str === 'string' && /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(str);
}
// Normalizar prefijos $2y/$2x a $2b para compatibilidad con bcrypt de Node
function normalizeBcryptHash(hash){
  if (typeof hash !== 'string') return hash;
  return hash.replace(/^\$2y\$/, '$2b$').replace(/^\$2x\$/, '$2b$');
}
async function hashPassword(plainOrHash){
  if (isBcryptHash(plainOrHash)) return normalizeBcryptHash(plainOrHash);
  return bcrypt.hash(String(plainOrHash), BCRYPT_ROUNDS);
}

// --- Helpers de fecha para membresía ---
function dateToLocalISO(d){
  const tz = d.getTimezoneOffset()*60000;
  return new Date(d.getTime() - tz).toISOString().slice(0,10);
}
function addDaysLocalISO(days){
  const d = new Date();
  d.setDate(d.getDate() + days);
  return dateToLocalISO(d);
}
function isMembershipActive(user){
  const exp = (user && user.membershipExpires || '').trim();
  if(!exp) return true; // si no hay fecha, no bloquea
  const today = dateToLocalISO(new Date());
  return today <= exp; // inclusive
}

async function seed() {
  await ensureDataDir();
  const users = await readUsers();
  if (!users || users.length === 0) {
    const defaultMembership = addDaysLocalISO(365);
    const adminPass = await hashPassword('admin123');
    const userPass = await hashPassword('user123');
    const seedUsers = [
      { id: 1, cc: '10000001', username: 'admin', name: 'Administrador', email: 'admin@example.com', password: adminPass, role: 'admin', artistsAssigned: [], membershipExpires: defaultMembership },
      { id: 2, cc: '20000002', username: 'user1', name: 'Usuario 1', email: 'user1@example.com', password: userPass, role: 'user', artistsAssigned: [], membershipExpires: defaultMembership }
    ];
    await saveUsers(seedUsers);
    console.log('Usuarios seed creados (admin/admin123, user1/user123)');
  }
}
seed().catch(console.error);

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}
function buildUserArtistStats(playlist, assignedRaw){
  const assigned = (assignedRaw||[]).map(normalizeArtist).filter(Boolean);
  if(!assigned.length) return null;

  const assignedSet = new Set(assigned);
  const snapshotLabels = playlist.map(p => p.scraped_at);
  const perArtistCounts = {};
  assigned.forEach(a => perArtistCounts[a] = new Array(snapshotLabels.length).fill(0));
  const combinedCounts = new Array(snapshotLabels.length).fill(0);
  const hourlyCounts = new Array(24).fill(0);
  const artistTotals = {};
  const trackCounter = {};
  const stationTotals = {};
  const cityTotals = {};
  const playsFlat = [];

  playlist.forEach((snap, idx) => {
    const datePart = (snap.scraped_at||'').split(' ')[0];
    (snap.items||[]).forEach(it => {
      const artNorm = normalizeArtist(it.artist);
      if(!assignedSet.has(artNorm)) return;

      perArtistCounts[artNorm][idx] += 1;
      combinedCounts[idx] += 1;

      const hourStr = (it.time_played||'00:00').split(':')[0];
      const hour = Number(hourStr);
      if(!Number.isNaN(hour) && hour>=0 && hour<24) hourlyCounts[hour] += 1;

      artistTotals[artNorm] = (artistTotals[artNorm]||0)+1;

      const trackKey = artNorm + '||' + (it.title||'').trim();
      trackCounter[trackKey] = (trackCounter[trackKey]||0)+1;

      const station_id = snap.station_id || it.station_id || 'unknown';
      const station_city = snap.station_city || it.station_city || 'N/A';
      const station_name = snap.station_name || it.station_name || 'N/A';
      const station_label = snap.station_label || it.station_label || ((station_city && station_name) ? (station_city+' - '+station_name) : station_name);

      stationTotals[station_label] = (stationTotals[station_label]||0)+1;
      cityTotals[station_city] = (cityTotals[station_city]||0)+1;

      const fullDateTimeStr = datePart + ' ' + (it.time_played||'00:00') + ':00';

      playsFlat.push({
        artist: it.artist,
        artistNorm: artNorm,
        title: it.title,
        time_played: it.time_played,
        datetime: fullDateTimeStr,
        snapshot: snap.scraped_at,
        station_id,
        station_city,
        station_name,
        station_label
      });
    });
  });

  playsFlat.sort((a,b) => a.datetime.localeCompare(b.datetime));

  const topTracks = Object.entries(trackCounter)
    .map(([key,count]) => {
      const [a,title] = key.split('||');
      return { artist: a, title, count };
    })
    .sort((a,b)=> b.count - a.count)
    .slice(0,10);

  const totalPlaysAssigned = Object.values(artistTotals).reduce((s,v)=>s+v,0);
  const uniqueTracksAssigned = Object.keys(trackCounter).length;
  let firstSeen = null, lastSeen = null;

  snapshotLabels.forEach(lbl => {
    if(!lbl) return;
    if(!firstSeen || lbl < firstSeen) firstSeen = lbl;
    if(!lastSeen || lbl > lastSeen) lastSeen = lbl;
  });

  const stationBreakdown = Object.entries(stationTotals).sort((a,b)=>b[1]-a[1]);
  const cityBreakdown = Object.entries(cityTotals).sort((a,b)=>b[1]-a[1]);

  return {
    artists: assigned,
    snapshotLabels,
    datasets: perArtistCounts,
    combinedCounts,
    hourly: {
      labels: Array.from({length:24},(_,h)=> (h+'').padStart(2,'0') ),
      counts: hourlyCounts
    },
    topTracks,
    recentPlays: playsFlat.slice(-25).reverse(),
    allPlays: playsFlat,
    totals: {
      totalPlaysAssigned,
      uniqueTracksAssigned,
      firstSeen,
      lastSeen,
      artistBreakdown: artistTotals,
      stationBreakdown,
      cityBreakdown
    }
  };
}

// ---- Fuzzy / Auto-asignación dinámica (MEJORADA) ----
function stripAccentsLower(str){
  return (str||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
}
function tokenize(str){
  return stripAccentsLower(str)
    .replace(/[^a-z0-9\s]+/g,' ')
    .split(/\s+/).filter(Boolean);
}
function scoreCandidate(userTokens, candTokens){
  const setU = new Set(userTokens);
  const setC = new Set(candTokens);
  let inter=0;
  setU.forEach(t=>{ if(setC.has(t)) inter++; });
  if(inter===0) return { coverage:0, extra:Infinity, jaccard:0, score:0 };
  const coverage = inter / setU.size;
  const union = new Set([...setU, ...setC]).size;
  const jaccard = inter / union;
  const extra = setC.size - inter;
  const score = coverage*2 + jaccard - extra*0.05;
  return { coverage, extra, jaccard, score };
}
function gatherMasterArtistCounts(playlist){
  const counts = {};
  for(const snap of (playlist||[])){
    for(const it of (snap.items||[])){
      if(it.artist){
        const name = normalize(it.artist);
        counts[name] = (counts[name]||0)+1;
      }
    }
  }
  return counts;
}
function gatherMasterArtists(playlist){
  return Object.keys(gatherMasterArtistCounts(playlist));
}
function chooseBestArtistVariant(userName, masterCounts, assigned, minCoverage = Number(process.env.MIN_ARTIST_COVERAGE || 0.6)){
  const userTokens = tokenize(userName).filter(Boolean);
  if(!userTokens.length) return null;
  const assignedSet = new Set((assigned||[]).map(a=>normalize(a)));
  let best = null;
  Object.entries(masterCounts).forEach(([artist, plays])=>{
    const candTokens = tokenize(artist);
    const sc = scoreCandidate(userTokens, candTokens);
    if(sc.coverage >= minCoverage){
      const data = {
        artist,
        plays,
        score: sc.score + sc.coverage * 2,
        coverage: sc.coverage,
        extra: sc.extra,
        length: artist.length
      };
      if(!best ||
         data.score > best.score ||
         (data.score === best.score && data.coverage > best.coverage) ||
         (data.score === best.score && data.coverage === best.coverage && data.plays > best.plays) ||
         (data.score === best.score && data.coverage === best.coverage && data.plays === best.plays && data.extra < best.extra) ||
         (data.score === best.score && data.coverage === best.coverage && data.plays === best.plays && data.extra === best.extra && data.length < best.length)
      ){
        best = data;
      }
    }
  });
  if(!best) return null;
  if(assignedSet.has(normalize(best.artist))) return null;
  return { artist: best.artist, coverage: best.coverage, plays: best.plays };
}
function coversAllUserTokens(userName, candidateName){
  const ut = tokenize(userName);
  const sc = scoreCandidate(ut, tokenize(candidateName));
  return sc.coverage === 1;
}
function updateUserAutoArtist(user, playlist){
  if(!user || !user.name) return null;
  const masterCounts = gatherMasterArtistCounts(playlist);
  if(!Object.keys(masterCounts).length) return null;
  const assigned = user.artistsAssigned || [];
  const candidateObj = chooseBestArtistVariant(user.name, masterCounts, assigned);
  if(!candidateObj) return null;
  const candidate = candidateObj.artist;

  let replaced = false;
  if(candidateObj.coverage === 1){
    for(let i=0;i<assigned.length;i++){
      const a = assigned[i];
      if(!masterCounts[a] && coversAllUserTokens(user.name, a)){
        assigned[i] = normalize(candidate);
        replaced = true;
        break;
      }
    }
  }
  if(!replaced){
    assigned.push(normalize(candidate));
  }
  const seen = new Set();
  user.artistsAssigned = assigned.filter(a=>{
    const k = normalizeArtist(a);
    if(seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return candidate;
}
// ------------------------------------------

// --- Job de auto-asignación continuo ---
let autoAssignRunning = false;
async function runAutoAssign(){
  if(autoAssignRunning) return;
  autoAssignRunning = true;
  try {
    const users = await readUsers();
    if(!users.length) return;
    const playlist = await readPlaylistMaster();
    if(!playlist.length) return;
    let changed = false;
    users.forEach(u => { if(updateUserAutoArtist(u, playlist)) changed = true; });
    if(changed) await saveUsers(users);
  } catch(err){
    console.error('Auto-assign error:', err.message);
  } finally {
    autoAssignRunning = false;
  }
}
setInterval(runAutoAssign, AUTO_ASSIGN_INTERVAL_MS);
runAutoAssign();
// --------------------------------------------------------

// Auth
app.get('/login', (req, res) => res.render('login', { error: null, active: '' }));

app.post('/login', async (req, res) => {
  try {
    let { username, password } = req.body;
    const usernameNorm = normalize(username);
    const users = await readUsers();
    const u = users.find(x => x.username === usernameNorm);

    if (!u) {
      return res.render('login', { error: 'Credenciales inválidas', active: '' });
    }

    // Validación contraseña (bcrypt o legacy texto plano con auto-migración)
    let valid = false;
    if (isBcryptHash(u.password)) {
      // comparar contra hash normalizado
      const storedNorm = normalizeBcryptHash(u.password);
      try {
        valid = await bcrypt.compare(String(password), storedNorm);
      } catch (e) {
        valid = false;
      }
      // si la comparación fue exitosa y el hash original tenía prefijo distinto, actualizamos al normalizado
      if (valid && storedNorm !== u.password) {
        u.password = storedNorm;
        await saveUsers(users);
      }
    } else {
      valid = u.password === String(password);
      // Migración automática a bcrypt si coincide
      if (valid) {
        u.password = await hashPassword(password);
        await saveUsers(users);
      }
    }

    if (!valid) {
      return res.render('login', { error: 'Credenciales inválidas', active: '' });
    }

    // Bloquea usuarios con membresía vencida; permite admin aunque esté vencida
    if (u.role !== 'admin' && !isMembershipActive(u)) {
      return res.render('login', { error: 'Membresía expirada. Contacte a un administrador.', active: '' });
    }

    // Auto-asignación al iniciar sesión
    const playlist = await readPlaylistMaster();
    const added = updateUserAutoArtist(u, playlist);
    if (added) await saveUsers(users);

    // Persistir sesión
    req.session.user = { id: u.id, username: u.username, role: u.role, name: u.name };
    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'Error interno de servidor', active: '' });
  }
});

app.get('/logout', (req, res) => { req.session.destroy(()=>res.redirect('/login')); });

//home
app.get('/', requireAuth, async (req, res) => {
  const playlist = await readPlaylistMaster();
  const artistCounts = {};
  let totalPlays = 0;
  const recent = [];
  const cityCounts = {};
  const stationCounts = {};

  for (const entry of (playlist || [])) {
    const items = Array.isArray(entry.items) ? entry.items : [];
    totalPlays += items.length;
    recent.push({ scraped_at: entry.scraped_at || 'unknown', count: items.length });

    for (const it of items) {
      if (it.artist) {
        const key = normalize(it.artist);
        artistCounts[key] = (artistCounts[key] || 0) + 1;
      }
      const city = (it.station_city || 'N/A').trim();
      cityCounts[city] = (cityCounts[city] || 0) + 1;
      const stationLabel = it.station_label ||
        ((it.station_city || 'N/A') + ' - ' + (it.station_name || 'N/A'));
      stationCounts[stationLabel] = (stationCounts[stationLabel] || 0) + 1;
    }
  }

  const topArtists = Object.entries(artistCounts)
    .map(([artist, count]) => ({ artist, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const topCities = Object.entries(cityCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([city, count]) => ({ city, count }));

  const topStations = Object.entries(stationCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([station, count]) => ({ station, count }));

  res.render('home', {
    active: 'home',
    stats: {
      uniqueArtists: Object.keys(artistCounts).length,
      totalPlays,
      recent: recent.slice(-40),
      topArtists,
      topCities,
      topStations
    }
  });
});

// ADMIN usuarios (LISTA)
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await readUsers();
  const playlist = await readPlaylistMaster();
  let changed = false;
  users.forEach(u => { if(updateUserAutoArtist(u, playlist)) changed = true; });
  if(changed) await saveUsers(users);
  const artistSet = new Set(gatherMasterArtists(playlist));
  const artists = Array.from(artistSet).sort();
  res.render('admin_users', { users, artists, active: 'users', created: req.query.created==='1', deleted: req.query.deleted==='1', updated: req.query.updated==='1' });
});

// NUEVO USUARIO (FORM)
app.get('/admin/users/new', requireAuth, requireAdmin, async (req, res) => {
  const playlist = await readPlaylistMaster();
  const artists = gatherMasterArtists(playlist).sort();
  res.render('admin_new_user', {
    active: 'users',
    artists,
    error: null,
    form: { cc:'', name:'', email:'', username:'', role:'user', artistsAssigned: [], membershipExpires: addDaysLocalISO(30) }
  });
});

// NUEVO USUARIO (POST)
app.post('/admin/users/new', requireAuth, requireAdmin, async (req, res) => {
  let { cc, name, email, username, password, role, membershipExpires } = req.body;
  let artists = req.body.artists || [];
  if (typeof artists === 'string') {
    artists = artists.split(',').map(a=>a.trim()).filter(Boolean);
  }
  if (!Array.isArray(artists)) artists = [];

  cc = normalize(cc);
  name = normalize(name);
  email = normalize(email);
  username = normalize(username);
  role = role === 'admin' ? 'admin' : 'user';
  membershipExpires = (membershipExpires || '').trim();

  const users = await readUsers();
  const errors = [];
  if (!cc) errors.push('CC requerida');
  if (!name) errors.push('Nombre requerido');
  if (!email) errors.push('Email requerido');
  if (!username) errors.push('Usuario requerido');
  if (!password || password.length < 4) errors.push('Password mínimo 4 chars');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(membershipExpires)) errors.push('Fecha de membresía inválida (YYYY-MM-DD)');
  // Unicidad (case-insensitive)
  if (users.some(u=> (u.username||'').toLowerCase() === username.toLowerCase())) errors.push('Usuario ya existe');
  if (users.some(u=> (u.email||'').toLowerCase() === email.toLowerCase())) errors.push('Email ya existe');
  if (users.some(u=> normalize(u.cc) === cc)) errors.push('CC ya existe');

  if (errors.length) {
    const playlist = await readPlaylistMaster();
    const artistsMaster = gatherMasterArtists(playlist).sort();
    return res.render('admin_new_user', {
      active: 'users',
      artists: artistsMaster,
      error: errors.join(', '),
      form: { cc, name, email, username, role, artistsAssigned: artists, membershipExpires }
    });
  }

  const playlist = await readPlaylistMaster();
  const masterCounts = gatherMasterArtistCounts(playlist);
  const candidateObj = chooseBestArtistVariant(name, masterCounts, artists);
  if(candidateObj){
    const candidate = candidateObj.artist;
    let replaced = false;
    if(candidateObj.coverage === 1){
      for(let i=0;i<artists.length;i++){
        if(!masterCounts[artists[i]] && coversAllUserTokens(name, artists[i])){
          artists[i] = candidate;
          replaced = true;
          break;
        }
      }
    }
    if(!replaced) artists.push(candidate);
  } else if(name){
    artists.push(name);
  }

  const seen = new Set();
  artists = artists.filter(a => {
    const key = normalizeArtist(a);
    if(seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const nextId = users.length ? Math.max(...users.map(u=>u.id||0))+1 : 1;
  const hashed = await hashPassword(password);
  users.push({
    id: nextId,
    cc,
    name,
    email,
    username,
    password: hashed,
    role,
    artistsAssigned: artists.map(a=>normalize(a)),
    membershipExpires
  });
  await saveUsers(users);
  res.redirect('/admin/users?created=1');
});

// EDIT (GET)
app.get('/admin/users/:id/edit', requireAuth, requireAdmin, async (req, res) => {
  const users = await readUsers();
  const u = users.find(x => x.id === Number(req.params.id));
  if (!u) return res.status(404).send('Usuario no encontrado');
  const playlist = await readPlaylistMaster();
  const artists = gatherMasterArtists(playlist).sort();
  res.render('admin_edit_user', { user: u, artists, active: 'users', error: null });
});

// EDIT (POST)
app.post('/admin/users/:id/edit', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  let { cc, name, email, username, password, role } = req.body;
  let membershipExpires = (req.body.membershipExpires || '').trim();
  let artists = req.body.artists || [];
  if (typeof artists === 'string') {
    artists = artists ? artists.split(',').map(a => a.trim()).filter(Boolean) : [];
  }
  if (!Array.isArray(artists)) artists = [];

  // Normalización previa para chequeos
  if (cc !== undefined) cc = normalize(cc);
  if (email !== undefined) email = normalize(email);
  if (username !== undefined) username = normalize(username);

  const users = await readUsers();
  const u = users.find(x => x.id === id);
  if (!u) return res.status(404).send('Usuario no encontrado');

  // Unicidad: username/email/cc contra otros usuarios (case-insensitive)
  if (username && username !== u.username && users.some(x=> (x.username||'').toLowerCase() === String(username).toLowerCase())) {
    const playlist = await readPlaylistMaster();
    const artistsMaster = gatherMasterArtists(playlist).sort();
    return res.render('admin_edit_user', { user: u, artists: artistsMaster, active:'users', error:'Usuario ya existe' });
  }
  if (email && email !== u.email && users.some(x=> (x.email||'').toLowerCase() === String(email).toLowerCase())) {
    const playlist = await readPlaylistMaster();
    const artistsMaster = gatherMasterArtists(playlist).sort();
    return res.render('admin_edit_user', { user: u, artists: artistsMaster, active:'users', error:'Email ya existe' });
  }
  if (cc && cc !== u.cc && users.some(x=> normalize(x.cc) === normalize(cc))) {
    const playlist = await readPlaylistMaster();
    const artistsMaster = gatherMasterArtists(playlist).sort();
    return res.render('admin_edit_user', { user: u, artists: artistsMaster, active:'users', error:'CC ya existe' });
  }
  if (membershipExpires && !/^\d{4}-\d{2}-\d{2}$/.test(membershipExpires)) {
    const playlist = await readPlaylistMaster();
    const artistsMaster = gatherMasterArtists(playlist).sort();
    return res.render('admin_edit_user', { user: u, artists: artistsMaster, active:'users', error:'Fecha de membresía inválida (YYYY-MM-DD)' });
  }

  u.cc = cc ? normalize(cc) : u.cc;
  u.name = name ? normalize(name) : u.name;
  u.email = (email !== undefined && email !== '') ? normalize(email) : (email === '' ? '' : u.email);
  u.username = username ? normalize(username) : u.username;
  if (role) u.role = (role === 'admin') ? 'admin' : 'user';
  if (password && password.trim() !== '') {
    u.password = await hashPassword(password);
  }
  u.artistsAssigned = artists.map(a => normalize(a));
  if (membershipExpires) {
    u.membershipExpires = membershipExpires;
  }
  await saveUsers(users);
  res.redirect('/admin/users?updated=1');
});

// DELETE
app.post('/admin/users/:id/delete', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  let users = await readUsers();
  const before = users.length;
  users = users.filter(u=>u.id !== id);
  if (users.length === before) return res.status(404).send('No encontrado');
  await saveUsers(users);
  res.redirect('/admin/users?deleted=1');
});

// Perfil
app.get('/profile', requireAuth, async (req, res) => {
  const users = await readUsers();
  const u = users.find(x => x.id === req.session.user.id);
  res.render('profile', { user: u, msg: null, active: 'profile' });
});
app.post('/profile', requireAuth, async (req, res) => {
  const { name, password } = req.body;
  const users = await readUsers();
  const u = users.find(x => x.id === req.session.user.id);
  if (!u) return res.status(404).send('Usuario no encontrado');
  if (name) u.name = name;
  if (password && password.trim() !== '') {
    u.password = await hashPassword(password);
  }
  await saveUsers(users);
  req.session.user.name = u.name;
  res.render('profile', { user: u, msg: 'Actualizado', active: 'profile' });
});

// Dashboard usuario
app.get('/user/dashboard', requireAuth, async (req, res) => {
  const users = await readUsers();
  const u = users.find(x => x.id === req.session.user.id);
  if (!u) return res.status(404).send('Usuario no encontrado');
  if (u.role !== 'user' && u.role !== 'admin') return res.status(403).send('Acceso restringido');
  const playlist = await readPlaylistMaster();
  const added = updateUserAutoArtist(u, playlist);
  if(added) await saveUsers(users);
  const assigned = (u.artistsAssigned||[]).filter(Boolean);
  let stats = null;
  if (assigned.length) stats = buildUserArtistStats(playlist, assigned);
  res.render('user_dashboard', {
    artist: assigned.join(', '),
    stats,
    active: 'dashboard'
  });
});

// API debug
app.get('/api/user/plays', requireAuth, async (req, res) => {
  const users = await readUsers();
  const u = users.find(x => x.id === req.session.user.id);
  if (!u) return res.json({ error:'Usuario no encontrado' });
  const playlist = await readPlaylistMaster();
  const stats = buildUserArtistStats(playlist, (u.artistsAssigned||[]));
  res.json(stats || {});
});

// ================= API PÚBLICA =================

// Token API (fijo o por variable de entorno)
const API_TOKEN = process.env.API_TOKEN || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.';
function requireApiToken(req, res, next) {
  const auth = req.headers.authorization || '';
  let token = '';
  if (auth.startsWith('Bearer ')) token = auth.slice(7).trim();
  else if (auth.startsWith('Token ')) token = auth.slice(6).trim();
  else if (req.query && req.query.token) token = String(req.query.token);
  if (token !== API_TOKEN) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  next();
}

// Crea o actualiza un usuario “activo” (por username); acepta password bcrypt o texto
// Campos esperados (JSON): membershipExpires, cc, name, username, email, password
app.post('/api/users/active', requireApiToken, async (req, res) => {
  try {
    let { membershipExpires, cc, name, username, email, password } = req.body;

    // Normalizar entradas
    const ccNorm = normalize(cc);
    const nameNorm = normalize(name);
    const usernameNorm = normalize(username);
    const emailNorm = normalize(email);

    // Validaciones mínimas
    const errors = [];
    if (!membershipExpires) errors.push('membershipExpires requerido');
    if (!ccNorm) errors.push('cc requerido');
    if (!nameNorm) errors.push('name requerido');
    if (!usernameNorm) errors.push('username requerido');
    if (!emailNorm) errors.push('email requerido');
    if (!password) errors.push('password requerido');
    if (password && !isBcryptHash(password) && String(password).length < 4) errors.push('password mínimo 4 chars');
    if (membershipExpires && !/^\d{4}-\d{2}-\d{2}$/.test(membershipExpires)) errors.push('membershipExpires debe ser YYYY-MM-DD');
    if (errors.length) return res.status(400).json({ ok: false, error: errors.join(', ') });

    const users = await readUsers();

    // Unicidad estricta (rechaza si ya existe)
    if (users.some(u => (u.username || '').toLowerCase() === usernameNorm.toLowerCase())) {
      return res.status(409).json({ ok: false, error: 'username ya existe' });
    }
    if (users.some(u => (u.email || '').toLowerCase() === emailNorm.toLowerCase())) {
      return res.status(409).json({ ok: false, error: 'email ya existe' });
    }
    if (users.some(u => normalize(u.cc) === ccNorm)) {
      return res.status(409).json({ ok: false, error: 'cc ya existe' });
    }

    const hashed = await hashPassword(password);
    const nextId = users.length ? Math.max(...users.map(u => u.id || 0)) + 1 : 1;

    const userObj = {
      id: nextId,
      cc: ccNorm,
      name: nameNorm,
      email: emailNorm,
      username: usernameNorm,
      password: hashed,
      role: 'user',
      artistsAssigned: [],
      membershipExpires: String(membershipExpires)
    };
    users.push(userObj);
    await saveUsers(users);

    const { password: _omit, ...publicUser } = userObj;
    return res.status(201).json({ ok: true, action: 'created', active: isMembershipActive(userObj), user: publicUser });
  } catch (e) {
    console.error('API /api/users/active error:', e);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});


// PUT: actualizar SOLO la fecha de membresía por CC
app.put('/api/users/cc/:cc/membership', requireApiToken, async (req, res) => {
  try {
    const rawCc = req.params.cc ?? '';
    const cc = normalize(rawCc);
    const { membershipExpires } = req.body || {};

    if (!cc) {
      return res.status(400).json({ ok: false, error: 'cc requerido en la URL' });
    }
    if (!membershipExpires) {
      return res.status(400).json({ ok: false, error: 'membershipExpires requerido' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(membershipExpires)) {
      return res.status(400).json({ ok: false, error: 'membershipExpires debe ser YYYY-MM-DD' });
    }

    const users = await readUsers();
    const u = users.find(x => normalize(x.cc) === cc);
    if (!u) {
      return res.status(404).json({ ok: false, error: 'usuario no encontrado por cc' });
    }

    u.membershipExpires = membershipExpires;
    await saveUsers(users);

    const { password: _omit, ...publicUser } = u;
    return res.status(200).json({ ok: true, action: 'updated', user: publicUser });
  } catch (e) {
    console.error('API PUT /api/users/cc/:cc/membership error:', e);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// =============================================

// ADMIN emisoras
async function readRadios() {
  try {
    const raw = await fs.readFile(RADIOS_FILE,'utf8');
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
async function saveRadios(radios) {
  await fs.writeFile(RADIOS_FILE, JSON.stringify(radios, null, 2), 'utf8');
}
function slugify(s){
  return (s||'')
    .normalize('NFD').replace(/[\u0300-\u036f]/g,'')
    .toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'')
    || 'radio';
}

async function seedRadios() {
  const rs = await readRadios();
  if(!rs.length){
    const demo = [
      { id:'medellin-olimpica', city:'Medellín', name:'Olímpica', url:'https://onlineradiobox.com/co/olmpicamedellin/playlist/?cs=co.olmpicabogota', active:true },
      { id:'bogota-olimpica', city:'Bogotá', name:'Olímpica', url:'https://onlineradiobox.com/co/olmpicabogota/playlist/?cs=co.olmpicabogota', active:true }
    ];
    await saveRadios(demo);
    console.log('Seed radios.json creado');
  }
}
seedRadios().catch(console.error);

// LISTA RADIOS
app.get('/admin/radios', requireAuth, requireAdmin, async (req,res)=>{
  const radios = await readRadios();
  res.render('admin_radios', {
    active:'radios',
    radios,
    created:req.query.created==='1',
    updated:req.query.updated==='1',
    deleted:req.query.deleted==='1',
    toggled:req.query.toggled==='1',
    error:null
  });
});

// NUEVA RADIO (GET)
app.get('/admin/radios/new', requireAuth, requireAdmin, (req,res)=>{
  res.render('admin_new_radio', { active:'radios', error:null, form:{ city:'', name:'', url:'', active:true } });
});

// NUEVA RADIO (POST)
app.post('/admin/radios/new', requireAuth, requireAdmin, async (req,res)=>{
  let { city, name, url, active } = req.body;
  city = (city||'').trim();
  name = (name||'').trim();
  url = (url||'').trim();
  const radios = await readRadios();
  const errors=[];
  if(!city) errors.push('Ciudad requerida');
  if(!name) errors.push('Nombre requerido');
  if(!url) errors.push('URL requerida');
  else {
    try { new URL(url); } catch { errors.push('URL inválida'); }
  }
  const id = slugify(`${city}-${name}`);
  if(radios.some(r=>r.id===id)) errors.push('ID ya existe');
  if(errors.length){
    return res.render('admin_new_radio', {
      active:'radios',
      error:errors.join(', '),
      form:{ city, name, url, active:active==='on' }
    });
  }
  radios.push({ id, city, name, url, active: active==='on' });
  await saveRadios(radios);
  res.redirect('/admin/radios?created=1');
});

// EDIT RADIO (GET)
app.get('/admin/radios/:id/edit', requireAuth, requireAdmin, async (req,res)=>{
  const radios = await readRadios();
  const r = radios.find(x=>x.id===req.params.id);
  if(!r) return res.status(404).send('No encontrada');
  res.render('admin_edit_radio', { active:'radios', radio:r, error:null });
});

// EDIT RADIO (POST)
app.post('/admin/radios/:id/edit', requireAuth, requireAdmin, async (req,res)=>{
  const radios = await readRadios();
  const r = radios.find(x=>x.id===req.params.id);
  if(!r) return res.status(404).send('No encontrada');
  let { city, name, url, active } = req.body;
  city = (city||'').trim();
  name = (name||'').trim();
  url = (url||'').trim();
  const errors=[];
  if(!city) errors.push('Ciudad requerida');
  if(!name) errors.push('Nombre requerido');
  if(!url) errors.push('URL requerida');
  else { try{ new URL(url); }catch{ errors.push('URL inválida'); } }
  if(errors.length){
    return res.render('admin_edit_radio', {
      active:'radios',
      radio:Object.assign({},r,{ city,name,url, active: active==='on'}),
      error:errors.join(', ')
    });
  }
  r.city = city;
  r.name = name;
  r.url = url;
  r.active = active==='on';
  await saveRadios(radios);
  res.redirect('/admin/radios?updated=1');
});

// TOGGLE (rápido)
app.post('/admin/radios/:id/toggle', requireAuth, requireAdmin, async (req,res)=>{
  const radios = await readRadios();
  const r = radios.find(x=>x.id===req.params.id);
  if(!r) return res.status(404).send('No encontrada');
  r.active = !r.active;
  await saveRadios(radios);
  res.redirect('/admin/radios?toggled=1');
});

// DELETE
app.post('/admin/radios/:id/delete', requireAuth, requireAdmin, async (req,res)=>{
  let radios = await readRadios();
  const before = radios.length;
  radios = radios.filter(r=>r.id!==req.params.id);
  if(radios.length===before) return res.status(404).send('No encontrada');
  await saveRadios(radios);
  res.redirect('/admin/radios?deleted=1');
});

const PORT = process.env.PORT || 3020;
app.listen(PORT, ()=>console.log(`REVDATA escuchando en http://localhost:${PORT} (auto-assign cada ${AUTO_ASSIGN_INTERVAL_MS}ms)`));