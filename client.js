// client.js
// Si usas Node <18 instala node-fetch y reemplaza fetch.
const BASE_URL = process.env.API_BASE_URL || 'http://localhost:3020';
const API_TOKEN = process.env.API_TOKEN || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'; // igual al del server
const AUTH_HEADER = `Bearer ${API_TOKEN}`;

async function postActiveUser(payload) {
  const url = `${BASE_URL}/api/users/active`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': AUTH_HEADER, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`POST /api/users/active -> ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

async function putMembershipByCC(cc, membershipDate) {
  const url = `${BASE_URL}/api/users/cc/${encodeURIComponent(cc)}/membership`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { 'Authorization': AUTH_HEADER, 'Content-Type': 'application/json' },
    body: JSON.stringify({ membershipExpires: membershipDate })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`PUT /api/users/cc/:cc/membership -> ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

(async () => {
  try {
    // 1) POST: crear/actualizar usuario activo
    const userPayload = {
      membershipExpires: '2026-12-31', // YYYY-MM-DD
      cc: '10000003',
      name: 'Usuario Demo CCs',
      username: 'demo_ccd',
      email: 'demo_cc@example.codm',
      password: 'demo1234' // texto plano; el server lo convierte a bcrypt
    };

    console.log('POST /api/users/active ...');
    const postResp = await postActiveUser(userPayload);
    console.log('Respuesta POST:', postResp);

    // 2) PUT: actualizar SOLO la fecha por CC
    const newDate = '2027-01-31';
    console.log(`PUT /api/users/cc/${userPayload.cc}/membership ...`);
    const putResp = await putMembershipByCC(userPayload.cc, newDate);
    console.log('Respuesta PUT:', putResp);

    console.log('Listo ✅');
  } catch (err) {
    console.error('Error:', err.message);
    process.exitCode = 1;
  }
})();
