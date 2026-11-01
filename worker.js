const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers }
});

function cookie(value, maxAge) {
  return `cr_admin=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

async function sign(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function isAdmin(request, env) {
  if (!env.SESSION_SECRET) return false;
  const raw = request.headers.get('Cookie') || '';
  const match = raw.match(/(?:^|;\s*)cr_admin=([^;]+)/);
  if (!match) return false;
  const parts = match[1].split('.');
  if (parts.length !== 2) return false;
  const [timestamp, signature] = parts;
  const time = Number(timestamp);
  if (!Number.isSafeInteger(time) || time > Date.now() || Date.now() - time > 8 * 60 * 60 * 1000) return false;
  return (await sign(env.SESSION_SECRET, timestamp)) === signature;
}

async function readJson(request) {
  try { return await request.json(); }
  catch { return null; }
}

function cleanText(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (path.startsWith('/api/')) {
      try {
        if (!env.DB) return json({ error: 'Associação D1 DB não configurada no Worker.' }, 500);

        if (path === '/api/health' && method === 'GET') {
          const result = await env.DB.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
          ).all();
          return json({ status: 'sucesso', projeto: 'CUIDAR E RECOMEÇAR V3', banco: 'conectado', tabelas: result.results });
        }

        if (path === '/api/categories' && method === 'GET') {
          const result = await env.DB.prepare('SELECT id, name, description FROM categories WHERE active = 1 ORDER BY name').all();
          return json(result.results);
        }

        if (path === '/api/products' && method === 'GET') {
          const result = await env.DB.prepare(
            `SELECT p.id, p.name, p.description, p.price, p.entry_price, p.image_url,
                    p.stock, p.active, p.featured, p.category_id, c.name AS category
             FROM products p LEFT JOIN categories c ON c.id = p.category_id
             WHERE p.active = 1 ORDER BY p.featured DESC, p.name`
          ).all();
          return json(result.results);
        }

        if (path === '/api/orders' && method === 'POST') {
          const body = await readJson(request);
          if (!body || !cleanText(body.full_name, 120) || !cleanText(body.whatsapp, 30) || !Array.isArray(body.items) || !body.items.length) {
            return json({ error: 'Informe nome, WhatsApp e pelo menos um produto.' }, 400);
          }
          if (body.items.length > 20) return json({ error: 'Limite de 20 itens por pedido.' }, 400);
          let total = 0;
          const items = [];
          for (const item of body.items) {
            const quantity = Math.max(1, Math.min(20, Math.floor(Number(item.quantity) || 1)));
            const product = await env.DB.prepare('SELECT id, name, price FROM products WHERE id = ? AND active = 1').bind(Number(item.product_id)).first();
            if (!product) return json({ error: 'Um dos produtos não está disponível.' }, 400);
            total += Number(product.price) * quantity;
            items.push({ ...product, quantity });
          }
          const customer = await env.DB.prepare(
            'INSERT INTO customers(full_name, whatsapp, address) VALUES (?, ?, ?)'
          ).bind(cleanText(body.full_name, 120), cleanText(body.whatsapp, 30), cleanText(body.address, 300)).run();
          const customerId = customer.meta.last_row_id;
          const order = await env.DB.prepare(
            "INSERT INTO orders(customer_id, total, status, notes) VALUES (?, ?, 'Recebido', ?)"
          ).bind(customerId, total, cleanText(body.notes, 1000)).run();
          const orderId = order.meta.last_row_id;
          for (const item of items) {
            await env.DB.prepare(
              'INSERT INTO order_items(order_id, product_id, product_name, quantity, unit_price) VALUES (?, ?, ?, ?, ?)'
            ).bind(orderId, item.id, item.name, item.quantity, item.price).run();
          }
          return json({ success: true, order_id: orderId, total }, 201);
        }

        if (path === '/api/login' && method === 'POST') {
          if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
            return json({ error: 'Configure ADMIN_PASSWORD e SESSION_SECRET nos segredos do Worker.' }, 500);
          }
          const body = await readJson(request);
          if (!body || typeof body.password !== 'string' || body.password !== env.ADMIN_PASSWORD) {
            return json({ error: 'Senha incorreta.' }, 401);
          }
          const timestamp = String(Date.now());
          const signature = await sign(env.SESSION_SECRET, timestamp);
          return json({ success: true }, 200, { 'Set-Cookie': cookie(`${timestamp}.${signature}`, 28800) });
        }

        if (path === '/api/logout' && method === 'POST') {
          return json({ success: true }, 200, { 'Set-Cookie': cookie('', 0) });
        }

        if (path === '/api/me' && method === 'GET') {
          return await isAdmin(request, env) ? json({ authenticated: true }) : json({ error: 'Não autenticado.' }, 401);
        }

        if (path.startsWith('/api/admin/')) {
          if (!(await isAdmin(request, env))) return json({ error: 'Acesso não autorizado.' }, 401);

          if (path === '/api/admin/stats' && method === 'GET') {
            const [products, orders, customers, sales] = await Promise.all([
              env.DB.prepare('SELECT COUNT(*) AS n FROM products').first(),
              env.DB.prepare('SELECT COUNT(*) AS n FROM orders').first(),
              env.DB.prepare('SELECT COUNT(*) AS n FROM customers').first(),
              env.DB.prepare("SELECT COALESCE(SUM(total),0) AS n FROM orders WHERE status NOT IN ('Cancelado')").first()
            ]);
            return json({ products: products.n, orders: orders.n, customers: customers.n, sales: sales.n });
          }
          if (path === '/api/admin/categories' && method === 'GET') {
            return json((await env.DB.prepare('SELECT id,name,description,active FROM categories ORDER BY name').all()).results);
          }
          if (path === '/api/admin/categories' && method === 'POST') {
            const body = await readJson(request);
            if (!body || !cleanText(body.name,100)) return json({error:'Informe o nome da categoria.'},400);
            const result = await env.DB.prepare('INSERT INTO categories(name,description,active) VALUES(?,?,1)')
              .bind(cleanText(body.name,100),cleanText(body.description,500)).run();
            return json({success:true,id:result.meta.last_row_id},201);
          }
          const categoryMatch = path.match(/^\/api\/admin\/categories\/(\d+)$/);
          if (categoryMatch && method === 'PATCH') {
            const body = await readJson(request);
            await env.DB.prepare('UPDATE categories SET active=? WHERE id=?')
              .bind(body && body.active ? 1 : 0,Number(categoryMatch[1])).run();
            return json({success:true});
          }
          if (path === '/api/admin/customers' && method === 'GET') {
            return json((await env.DB.prepare(`SELECT c.id,c.full_name,c.whatsapp,c.address,
              COUNT(o.id) AS orders,COALESCE(SUM(CASE WHEN o.status != 'Cancelado' THEN o.total ELSE 0 END),0) AS total
              FROM customers c LEFT JOIN orders o ON o.customer_id=c.id
              GROUP BY c.id ORDER BY c.id DESC LIMIT 500`).all()).results);
          }
          if (path === '/api/admin/reports' && method === 'GET') {
            const r = await env.DB.prepare(`SELECT COUNT(*) AS orders,
              SUM(CASE WHEN status IN ('Confirmado','Preparando','Entregue') THEN 1 ELSE 0 END) AS completed,
              SUM(CASE WHEN status='Cancelado' THEN 1 ELSE 0 END) AS cancelled,
              COALESCE(SUM(CASE WHEN status!='Cancelado' THEN total ELSE 0 END),0) AS sales
              FROM orders`).first();
            return json({orders:r.orders||0,completed:r.completed||0,cancelled:r.cancelled||0,sales:r.sales||0});
          }
          if (path === '/api/admin/products' && method === 'GET') {
            return json((await env.DB.prepare('SELECT * FROM products ORDER BY id DESC').all()).results);
          }
          if (path === '/api/admin/products' && method === 'POST') {
            const body = await readJson(request);
            if (!body || !cleanText(body.name, 160) || !Number.isFinite(Number(body.price)) || Number(body.price) < 0) {
              return json({ error: 'Informe nome e preço válido.' }, 400);
            }
            const result = await env.DB.prepare(
              'INSERT INTO products(category_id,name,description,price,entry_price,image_url,stock,active,featured) VALUES(?,?,?,?,?,?,?,?,?)'
            ).bind(Number(body.category_id) || null, cleanText(body.name, 160), cleanText(body.description, 1500), Number(body.price), body.entry_price === null || body.entry_price === '' ? null : Number(body.entry_price), cleanText(body.image_url, 1000), Math.max(0, Number(body.stock) || 0), body.active ? 1 : 0, body.featured ? 1 : 0).run();
            return json({ success: true, id: result.meta.last_row_id }, 201);
          }
          const productMatch = path.match(/^\/api\/admin\/products\/(\d+)$/);
          if (productMatch && method === 'PUT') {
            const body = await readJson(request);
            if (!body || !cleanText(body.name, 160) || !Number.isFinite(Number(body.price)) || Number(body.price) < 0) return json({ error: 'Dados do produto inválidos.' }, 400);
            await env.DB.prepare(
              'UPDATE products SET category_id=?,name=?,description=?,price=?,entry_price=?,image_url=?,stock=?,active=?,featured=?,updated_at=CURRENT_TIMESTAMP WHERE id=?'
            ).bind(Number(body.category_id) || null, cleanText(body.name, 160), cleanText(body.description, 1500), Number(body.price), body.entry_price === null || body.entry_price === '' ? null : Number(body.entry_price), cleanText(body.image_url, 1000), Math.max(0, Number(body.stock) || 0), body.active ? 1 : 0, body.featured ? 1 : 0, Number(productMatch[1])).run();
            return json({ success: true });
          }
          if (productMatch && method === 'DELETE') {
            const linked = await env.DB.prepare('SELECT COUNT(*) AS total FROM order_items WHERE product_id = ?').bind(Number(productMatch[1])).first();
            if (Number(linked.total) > 0) {
              await env.DB.prepare('UPDATE products SET active=0 WHERE id=?').bind(Number(productMatch[1])).run();
              return json({ success: true, archived: true });
            }
            await env.DB.prepare('DELETE FROM products WHERE id=?').bind(Number(productMatch[1])).run();
            return json({ success: true, archived: false });
          }
          if (path === '/api/admin/orders' && method === 'GET') {
            return json((await env.DB.prepare(
              'SELECT o.id,o.total,o.status,o.created_at,c.full_name,c.whatsapp FROM orders o JOIN customers c ON c.id=o.customer_id ORDER BY o.id DESC LIMIT 200'
            ).all()).results);
          }
          const orderMatch = path.match(/^\/api\/admin\/orders\/(\d+)$/);
          if (orderMatch && method === 'PATCH') {
            const body = await readJson(request);
            const allowed = ['Recebido', 'Em atendimento', 'Negociando', 'Confirmado', 'Preparando', 'Entregue', 'Cancelado'];
            if (!body || !allowed.includes(body.status)) return json({ error: 'Status inválido.' }, 400);
            await env.DB.prepare('UPDATE orders SET status=? WHERE id=?').bind(body.status, Number(orderMatch[1])).run();
            return json({ success: true });
          }
          return json({ error: 'Rota administrativa não encontrada.' }, 404);
        }
        return json({ error: 'Rota da API não encontrada.' }, 404);
      } catch (error) {
        return json({ error: error?.message || 'Erro interno.' }, 500);
      }
    }

    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('CUIDAR E RECOMEÇAR V3 — configure os arquivos estáticos.');
  }
};
