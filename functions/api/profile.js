export async function onRequest(context) {
  const { request, env } = context;

  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 401,
    });
  }

  const token = auth.slice(7);
  const [headerB64, payloadB64, sigB64] = token.split('.');
  if (!headerB64 || !payloadB64 || !sigB64) {
    return new Response(JSON.stringify({ error: 'invalid_token' }), {
      status: 401,
    });
  }

  const keyData = new TextEncoder().encode(env.JWT_SECRET);
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const verified = await crypto.subtle.verify(
    'HMAC',
    key,
    Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0)),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  );

  if (!verified) {
    return new Response(JSON.stringify({ error: 'invalid_signature' }), {
      status: 401,
    });
  }

  const payload = JSON.parse(atob(payloadB64));
  const user = await env.DB.prepare(
    'SELECT id, email, created_at FROM users WHERE id = ?'
  )
    .bind(payload.sub)
    .first();

  if (!user) {
    return new Response(JSON.stringify({ error: 'not_found' }), {
      status: 404,
    });
  }

  return new Response(JSON.stringify(user), {
    headers: { 'content-type': 'application/json' },
  });
}