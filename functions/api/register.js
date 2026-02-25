export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const { email, password } = await request.json();
  if (!email || !password || password.length < 8) {
    return new Response(JSON.stringify({ error: 'invalid_input' }), {
      status: 400,
    });
  }

  // 生成盐值
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();

  // 派生 PBKDF2 哈希
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
  const saltB64 = btoa(String.fromCharCode(...salt));

  // 写入数据库
  const now = Math.floor(Date.now() / 1000);
  try {
    await env.DB.prepare(
      'INSERT INTO users (email, password_hash, salt, created_at) VALUES (?, ?, ?, ?)'
    )
      .bind(email.toLowerCase(), hashB64, saltB64, now)
      .run();
  } catch (e) {
    return new Response(JSON.stringify({ error: 'email_exists' }), {
      status: 409,
    });
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 201,
    headers: { 'content-type': 'application/json' },
  });
}