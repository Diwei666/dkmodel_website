export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const { email, password } = await request.json();
  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'invalid_input' }), {
      status: 400,
    });
  }

  const row = await env.DB.prepare(
    'SELECT id, password_hash, salt FROM users WHERE email = ?'
  )
    .bind(email.toLowerCase())
    .first();

  if (!row) {
    return new Response(JSON.stringify({ error: 'user_not_found' }), {
      status: 404,
    });
  }

  // 验证密码
  const salt = Uint8Array.from(atob(row.salt), (c) => c.charCodeAt(0));
  const encoder = new TextEncoder();

  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    256
  );

  const hashArray = new Uint8Array(derivedBits);
  const hashB64 = btoa(String.fromCharCode(...hashArray));

  if (hashB64 !== row.password_hash) {
    return new Response(JSON.stringify({ error: 'wrong_password' }), {
      status: 401,
    });
  }

  // 签发简单 JWT
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(
    JSON.stringify({
      sub: row.id,
      email,
      iat: Math.floor(Date.now() / 1000),
    })
  );

  const keyData = new TextEncoder().encode(env.JWT_SECRET);
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${header}.${payload}`)
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const token = `${header}.${payload}.${sigB64}`;

  return new Response(JSON.stringify({ token }), {
    headers: { 'content-type': 'application/json' },
  });
}