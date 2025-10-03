const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const cron = require('node-cron');

const RADIOS_FILE = path.join(__dirname, 'data', 'radios.json');
const OUT_DIR = path.join(__dirname, 'data');
const MASTER_FILE = path.join(OUT_DIR, 'playlist_history.json');

function bogotaNowString() {
  return new Date().toLocaleString('sv', { timeZone: 'America/Bogota' }).replace('T', ' ');
}

// Leer listado emisoras
async function loadRadios() {
  try {
    const raw = await fs.readFile(RADIOS_FILE, 'utf8');
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) throw new Error('radios.json no es un array');
    return arr;
  } catch (e) {
    console.warn('No se pudo leer radios.json, fallback:', e.message);
    return [{
      id: 'default',
      city: 'N/A',
      name: 'Default',
      url: 'https://onlineradiobox.com/co/olmpicamedellin/playlist/?cs=co.olmpicabogota',
      active: true
    }];
  }
}

// Seleccionar emisoras a procesar (activas; si ninguna activa => todas)
function pickTargetRadios(radios) {
  const actives = radios.filter(r => r.active);
  return actives.length ? actives : radios;
}

let running = false;

async function scrapeStation(station) {
  if (!station.url) {
    console.warn(`Saltada estación ${station.id || station.name}: sin url`);
    return null;
  }
  try {
    const res = await axios.get(station.url, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      timeout: 20000
    });
    const $ = cheerio.load(res.data);
    const items = [];
    $('table.tablelist-schedule tbody tr').each((_, tr) => {
      const $tr = $(tr);
      const time = $tr.find('.time--schedule').first().text().trim() || null;
      const $link = $tr.find('.track_history_item a.ajax').first();
      const linkHref = $link.attr('href')
        ? new URL($link.attr('href'), 'https://onlineradiobox.com').toString()
        : null;
      let rawText = $link.text().trim();
      if (!rawText) rawText = $tr.find('.track_history_item').text().trim() || null;

      let artist = null;
      let title = rawText;
      if (rawText && rawText.includes(' - ')) {
        const parts = rawText.split(' - ');
        artist = parts[0].trim();
        title = parts.slice(1).join(' - ').trim();
      }

      items.push({
        station_id: station.id,
        station_city: station.city,
        station_name: station.name,
        station_label: `${station.city || ''} - ${station.name || ''}`.trim(),
        station_url: station.url,
        date_played: bogotaNowString().slice(0, 10),
        time_played: time,
        artist,
        title,
        raw: rawText,
        link: linkHref
      });
    });

    const scraped_at = bogotaNowString();
    const filename = `playlist-${station.id}-${scraped_at.replace(/[: ]/g, '-')}.json`;
    await fs.mkdir(OUT_DIR, { recursive: true });

    const out = {
      source: station.url,
      station_id: station.id,
      station_city: station.city,
      station_name: station.name,
      station_label: `${station.city || ''} - ${station.name || ''}`.trim(),
      station_url: station.url,
      scraped_at,
      count: items.length,
      items
    };
    await fs.writeFile(path.join(OUT_DIR, filename), JSON.stringify(out, null, 2), 'utf8');
    console.log(`[${scraped_at}] OK ${station.id} (${items.length}) -> ${filename}`);
    return out;
  } catch (e) {
    console.error(`Error estación ${station.id}:`, e.message);
    return null;
  }
}

async function appendToMaster(newBlocks) {
  let master = [];
  try {
    const raw = await fs.readFile(MASTER_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) master = parsed;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  master.push(...newBlocks);
  await fs.writeFile(MASTER_FILE, JSON.stringify(master, null, 2), 'utf8');
  return master.length;
}

async function scrapeAllStations() {
  if (running) {
    console.log('Saltado: ciclo previo en curso');
    return;
  }
  running = true;
  console.log(`[${bogotaNowString()}] Inicio scraping múltiple`);
  try {
    const radios = await loadRadios();
    const targets = pickTargetRadios(radios);
    const collected = [];
    for (const st of targets) {
      const block = await scrapeStation(st);
      if (block) collected.push(block);
      await new Promise(r => setTimeout(r, 400));
    }
    if (collected.length) {
      const total = await appendToMaster(collected);
      console.log(`Guardadas ${collected.length} estaciones. Master total: ${total}`);
    } else {
      console.warn('Sin resultados guardados.');
    }
  } catch (e) {
    console.error('Error global:', e.stack || e.message);
  } finally {
    running = false;
    console.log(`[${bogotaNowString()}] Fin scraping múltiple`);
  }
}

// Logs iniciales
console.log('Hora sistema ISO:', new Date().toISOString());
console.log('Hora Colombia:', bogotaNowString());

// Cron ejemplo (descomentarlo y ajustar horario)
 cron.schedule('58 23 * * *', () => {
   console.log('Cron ->', bogotaNowString());
   scrapeAllStations();
 }, { scheduled: true, timezone: 'America/Bogota' });

// Ejecución inmediata
// scrapeAllStations();

process.on('unhandledRejection', e => console.error('UnhandledRejection:', e));
process.on('uncaughtException', e => console.error('UncaughtException:', e));