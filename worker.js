const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', ...extra }
});

function cookieOptions(maxAge = 60 * 60 * 24 * 7) {
  return `Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function normalizeWhatsApp(value = '') {
  const digits = String(value).replace(/\D/g, '');
  if (!digits) return '2290197014571';
  if (digits.startsWith('229')) return digits;
  if (digits.startsWith('01') && digits.length === 10) return '229' + digits;
  if (digits.length === 8) return '22901' + digits;
  return digits;
}

async function makeToken(env) {
  const data = `${Date.now()}.${crypto.randomUUID()}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.ADMIN_PASSWORD),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  return `${data}.${b64}`;
}

async function validToken(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)bm_admin=([^;]+)/);
  if (!match || !env.ADMIN_PASSWORD) return false;
  const parts = match[1].split('.');
  if (parts.length < 3) return false;
  const data = `${parts[0]}.${parts[1]}`;
  const supplied = parts.slice(2).join('.');
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.ADMIN_PASSWORD),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  try {
    const bin = atob(supplied.replace(/-/g,'+').replace(/_/g,'/'));
    return await crypto.subtle.verify('HMAC', key,
      Uint8Array.from(bin, c => c.charCodeAt(0)), new TextEncoder().encode(data));
  } catch { return false; }
}

async function requireAdmin(request, env) {
  if (!(await validToken(request, env))) return json({ error: 'Non autorisé' }, 401);
  return null;
}

async function getSetting(env, key, fallback = '') {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
  return row?.value ?? fallback;
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === '/api/admin/login' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (!env.ADMIN_PASSWORD || !body.password || body.password !== env.ADMIN_PASSWORD) {
      return json({ error: 'Mot de passe incorrect' }, 401);
    }
    const token = await makeToken(env);
    return json({ ok: true }, 200, { 'Set-Cookie': `bm_admin=${token}; ${cookieOptions()}` });
  }

  if (path === '/api/admin/logout' && method === 'POST') {
    return json({ ok: true }, 200, { 'Set-Cookie': `bm_admin=; ${cookieOptions(0)}` });
  }

  if (path === '/api/admin/me' && method === 'GET') {
    return json({ authenticated: await validToken(request, env) });
  }

  if (path === '/api/products' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM products WHERE active=1 ORDER BY id DESC').all();
    return json(results);
  }

  if (path === '/api/banners' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM banners WHERE active=1 ORDER BY sort_order ASC, id DESC').all();
    return json(results);
  }

  if (path === '/api/settings' && method === 'GET') {
    return json({
      whatsapp_number: normalizeWhatsApp(await getSetting(env, 'whatsapp_number', '0197014571')),
      store_name: await getSetting(env, 'store_name', 'BENIN SHOP')
    });
  }

  const admin = await requireAdmin(request, env);
  if (admin) return admin;

  if (path === '/api/admin/products' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM products ORDER BY id DESC').all();
    return json(results);
  }

  if (path === '/api/admin/products' && method === 'POST') {
    const b = await request.json();
    if (!String(b.name || '').trim()) return json({ error: 'Le nom est obligatoire' }, 400);
    const r = await env.DB.prepare(`INSERT INTO products
      (name,description,name_en,name_zh,description_en,description_zh,price,category,category_en,category_zh,image_key,emoji,stock,active)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(
        b.name || '', b.description || '', b.name_en || '', b.name_zh || '',
        b.description_en || '', b.description_zh || '', Number(b.price) || 0,
        b.category || 'Maison', b.category_en || '', b.category_zh || '',
        b.image_key || '', b.emoji || '🛍️', Number(b.stock) || 0, b.active === false ? 0 : 1
      ).run();
    return json({ ok: true, id: r.meta.last_row_id });
  }

  const pm = path.match(/^\/api\/admin\/products\/(\d+)$/);
  if (pm && method === 'PUT') {
    const b = await request.json();
    if (!String(b.name || '').trim()) return json({ error: 'Le nom est obligatoire' }, 400);
    await env.DB.prepare(`UPDATE products SET
      name=?,description=?,name_en=?,name_zh=?,description_en=?,description_zh=?,price=?,
      category=?,category_en=?,category_zh=?,image_key=?,emoji=?,stock=?,active=?,updated_at=CURRENT_TIMESTAMP
      WHERE id=?`)
      .bind(
        b.name || '', b.description || '', b.name_en || '', b.name_zh || '',
        b.description_en || '', b.description_zh || '', Number(b.price) || 0,
        b.category || 'Maison', b.category_en || '', b.category_zh || '',
        b.image_key || '', b.emoji || '🛍️', Number(b.stock) || 0,
        b.active === false ? 0 : 1, Number(pm[1])
      ).run();
    return json({ ok: true });
  }
  if (pm && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM products WHERE id=?').bind(Number(pm[1])).run();
    return json({ ok: true });
  }

  if (path === '/api/admin/banners' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM banners ORDER BY sort_order ASC, id DESC').all();
    return json(results);
  }
  if (path === '/api/admin/banners' && method === 'POST') {
    const b = await request.json();
    if (!b.image_key) return json({ error: 'Veuillez d’abord téléverser une image' }, 400);
    const r = await env.DB.prepare(`INSERT INTO banners
      (image_key,title,subtitle,title_en,title_zh,subtitle_en,subtitle_zh,button_text,button_text_en,button_text_zh,button_link,sort_order,active)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(
        b.image_key, b.title || '', b.subtitle || '', b.title_en || '', b.title_zh || '',
        b.subtitle_en || '', b.subtitle_zh || '', b.button_text || 'Voir les produits',
        b.button_text_en || 'View products', b.button_text_zh || '查看商品', b.button_link || '#products',
        Number(b.sort_order) || 0, b.active === false ? 0 : 1
      ).run();
    return json({ ok: true, id: r.meta.last_row_id });
  }
  const bm = path.match(/^\/api\/admin\/banners\/(\d+)$/);
  if (bm && method === 'PUT') {
    const b = await request.json();
    if (!b.image_key) return json({ error: 'Veuillez d’abord téléverser une image' }, 400);
    await env.DB.prepare(`UPDATE banners SET image_key=?,title=?,subtitle=?,title_en=?,title_zh=?,subtitle_en=?,subtitle_zh=?,
      button_text=?,button_text_en=?,button_text_zh=?,button_link=?,sort_order=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`)
      .bind(
        b.image_key, b.title || '', b.subtitle || '', b.title_en || '', b.title_zh || '',
        b.subtitle_en || '', b.subtitle_zh || '', b.button_text || 'Voir les produits',
        b.button_text_en || 'View products', b.button_text_zh || '查看商品', b.button_link || '#products',
        Number(b.sort_order) || 0, b.active === false ? 0 : 1, Number(bm[1])
      ).run();
    return json({ ok: true });
  }
  if (bm && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM banners WHERE id=?').bind(Number(bm[1])).run();
    return json({ ok: true });
  }

  if (path === '/api/admin/settings' && method === 'GET') {
    return json({
      whatsapp_number: await getSetting(env, 'whatsapp_number', '0197014571'),
      store_name: await getSetting(env, 'store_name', 'BENIN SHOP')
    });
  }
  if (path === '/api/admin/settings' && method === 'POST') {
    const b = await request.json();
    const whatsapp = normalizeWhatsApp(b.whatsapp_number || '0197014571');
    if (!whatsapp || whatsapp.length < 10) return json({ error: 'Numéro WhatsApp invalide' }, 400);
    await env.DB.prepare(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
      .bind('whatsapp_number', whatsapp).run();
    if (b.store_name) {
      await env.DB.prepare(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
        .bind('store_name', String(b.store_name).slice(0,100)).run();
    }
    return json({ ok: true, whatsapp_number: whatsapp });
  }


  return json({ error: 'Not found' }, 404);
}



const STATIC_FILES = {
  "index.html": "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Benin Market \u2014 Votre boutique en ligne</title><meta name=\"description\" content=\"Benin Market \u2014 produits du quotidien, commande simple par WhatsApp.\"><link rel=\"stylesheet\" href=\"style.css\"></head><body>\n<header class=\"topbar\"><div class=\"wrap nav\"><a class=\"logo\" href=\"#\"><span>BM</span> Benin Market</a><div class=\"nav-actions\"><a href=\"#categories\" data-i18n=\"categories\">Cat\u00e9gories</a><a href=\"#products\" data-i18n=\"products\">Produits</a><button class=\"cart-btn\" onclick=\"openCart()\">\ud83d\uded2 Panier <b id=\"cartCount\">0</b></button></div></div><div class=\"language-switcher\" aria-label=\"Language\">\n<select id=\"languageSelect\" onchange=\"setLanguage(this.value)\">\n<option value=\"fr\">\ud83c\uddeb\ud83c\uddf7 Fran\u00e7ais</option>\n<option value=\"en\">\ud83c\uddec\ud83c\udde7 English</option>\n<option value=\"zh\">\ud83c\udde8\ud83c\uddf3 \u4e2d\u6587</option>\n</select>\n</div>\n</header>\n<main><section class=\"hero\"><div id=\"bannerWrap\" class=\"banner-wrap\"></div><div class=\"wrap hero-grid\"><div><p class=\"eyebrow\">\ud83d\udecd\ufe0f BOUTIQUE EN LIGNE</p><h1>Tout ce dont vous avez besoin,<br><strong>simplement.</strong></h1><p class=\"hero-text\">D\u00e9couvrez nos produits, ajoutez-les au panier et commandez directement sur WhatsApp.</p><a class=\"primary\" href=\"#products\">Voir les produits</a></div><div class=\"hero-card\"><div class=\"hero-icon\">\ud83d\uded2</div><h3>Commande rapide</h3><p>Pas besoin de cr\u00e9er un compte. Choisissez vos produits et envoyez votre commande sur WhatsApp.</p></div></div></section>\n<section id=\"categories\" class=\"section wrap\"><div class=\"section-head\"><h2 data-i18n=\"categories\">Cat\u00e9gories</h2><span>Choisissez une cat\u00e9gorie</span></div><div class=\"categories\"><button onclick=\"filterCat('Tous')\">\ud83d\udecd\ufe0f <span>Tous</span></button><button onclick=\"filterCat('Maison')\">\ud83c\udfe0 <span>Maison</span></button><button onclick=\"filterCat('Cuisine')\">\ud83c\udf73 <span>Cuisine</span></button><button onclick=\"filterCat('\u00c9lectronique')\">\ud83d\udcf1 <span>\u00c9lectronique</span></button><button onclick=\"filterCat('Beaut\u00e9')\">\ud83e\uddf4 <span>Beaut\u00e9</span></button></div></section>\n<section id=\"products\" class=\"section wrap\"><div class=\"section-head\"><h2>Produits populaires</h2><span id=\"resultLabel\">Tous les produits</span></div><div class=\"searchbar\"><input id=\"searchInput\" data-i18n-placeholder=\"search\" placeholder=\"Rechercher un produit...\" oninput=\"searchProducts(this.value)\"></div><div id=\"productGrid\" class=\"products\"></div></section></main>\n<div id=\"cartModal\" class=\"modal\" onclick=\"if(event.target===this)closeCart()\"><div class=\"modal-box\"><button class=\"close\" onclick=\"closeCart()\">\u00d7</button><h2>Votre panier</h2><div id=\"cartItems\"></div><div class=\"total\"><span>Total</span><strong id=\"cartTotal\">0 FCFA</strong></div><button class=\"whatsapp full\" onclick=\"checkout()\">\ud83d\udcf2 Commander sur WhatsApp</button><p class=\"small\">Le vendeur confirmera la disponibilit\u00e9, le prix final et la livraison.</p></div></div>\n<footer><div class=\"wrap footer-grid\"><div><div class=\"logo\"><span>BM</span> Benin Market</div><p>Votre boutique en ligne au B\u00e9nin.</p></div><div><b>Contact</b><p>WhatsApp : 0197014571</p><p>Cotonou, B\u00e9nin</p></div><div><b>Horaires</b><p>Lun \u2014 Sam : 08:00 \u2014 20:00</p></div></div><div class=\"copyright\">\u00a9 2026 Benin Market. Tous droits r\u00e9serv\u00e9s.</div></footer>\n<script src=\"i18n.js\"></script>\n<script src=\"script.js\"></script></body></html>\n",
  "style.css": ":root{--ink:#18202a;--muted:#697586;--line:#e7e9ee;--bg:#f7f8fa;--white:#fff;--accent:#18a957;--accent2:#0d7d40}\n*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:Inter,Arial,sans-serif;color:var(--ink);background:var(--bg)}\n.wrap{width:min(1120px,92%);margin:auto}.topbar{position:sticky;top:0;z-index:20;background:rgba(255,255,255,.95);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}\n.nav{height:70px;display:flex;align-items:center;justify-content:space-between}.logo{font-weight:800;font-size:20px;color:var(--ink);text-decoration:none;display:flex;align-items:center;gap:9px}.logo span{display:grid;place-items:center;width:36px;height:36px;border-radius:10px;background:var(--accent);color:#fff;font-size:13px}\n.nav-actions{display:flex;gap:24px;align-items:center}.nav-actions a{color:#4e5968;text-decoration:none;font-size:14px}.cart-btn{border:0;background:#eef8f2;padding:10px 14px;border-radius:10px;color:var(--accent2);font-weight:700;cursor:pointer}\n.hero{background:linear-gradient(135deg,#ecfbf2,#fff);padding:74px 0}.hero-grid{display:grid;grid-template-columns:1.4fr .8fr;gap:55px;align-items:center}.eyebrow{color:var(--accent2);font-size:13px;font-weight:800;letter-spacing:1px}.hero h1{font-size:52px;line-height:1.08;margin:12px 0 18px}.hero h1 strong{color:var(--accent2)}.hero-text{color:var(--muted);font-size:18px;line-height:1.6;max-width:620px}.primary{display:inline-block;margin-top:18px;background:var(--accent);color:#fff;padding:14px 22px;border-radius:10px;text-decoration:none;font-weight:800}.hero-card{background:#fff;border:1px solid var(--line);border-radius:22px;padding:34px;box-shadow:0 18px 50px rgba(20,30,40,.07)}.hero-icon{font-size:54px}.hero-card p{color:var(--muted);line-height:1.6}\n.section{padding:55px 0 15px}.section-head{display:flex;justify-content:space-between;align-items:end;margin-bottom:22px}.section-head h2{font-size:28px;margin:0}.section-head span{color:var(--muted);font-size:14px}\n.categories{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.categories button{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px 10px;cursor:pointer;font-weight:700;color:#3b4552}.categories button:first-child{border-color:#bce7cc;background:#f0fbf4}.categories span{display:block;margin-top:8px;font-size:13px}\n.products{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}.card{background:#fff;border:1px solid var(--line);border-radius:16px;overflow:hidden}.pic{height:190px;background:#f1f3f5;display:grid;place-items:center;font-size:70px}.card-body{padding:16px}.tag{font-size:11px;color:var(--accent2);font-weight:800;text-transform:uppercase}.card h3{font-size:16px;margin:8px 0}.price{font-weight:900;font-size:18px}.add{width:100%;border:0;background:var(--ink);color:#fff;border-radius:9px;padding:11px;margin-top:13px;font-weight:800;cursor:pointer}.add:hover{background:#000}\n.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:50;padding:30px}.modal-box{background:#fff;width:min(520px,100%);max-height:90vh;overflow:auto;margin:auto;border-radius:18px;padding:26px;position:relative}.close{position:absolute;right:16px;top:10px;border:0;background:none;font-size:30px;cursor:pointer}.cart-row{display:flex;gap:12px;padding:13px 0;border-bottom:1px solid var(--line);align-items:center}.cart-row .emoji{font-size:32px}.cart-row .info{flex:1}.qty button{border:1px solid var(--line);background:#fff;width:28px;height:28px;border-radius:6px}.total{display:flex;justify-content:space-between;padding:20px 0;font-size:20px}.whatsapp{background:#25D366;border:0;color:#fff;font-weight:900;border-radius:10px;padding:14px;cursor:pointer}.full{width:100%}.small{font-size:12px;color:var(--muted);text-align:center}\nfooter{margin-top:70px;background:#171d24;color:#d8dee6;padding:42px 0 15px}.footer-grid{display:grid;grid-template-columns:2fr 1fr 1fr;gap:30px}.footer-grid .logo{color:#fff}.footer-grid p{color:#9da8b5;font-size:13px;line-height:1.7}.copyright{text-align:center;border-top:1px solid #303741;margin-top:28px;padding-top:15px;color:#8994a0;font-size:12px}\n@media(max-width:800px){.nav-actions a{display:none}.hero{padding:48px 0}.hero-grid{grid-template-columns:1fr}.hero h1{font-size:40px}.categories{grid-template-columns:repeat(2,1fr)}.products{grid-template-columns:repeat(2,1fr)}.footer-grid{grid-template-columns:1fr}.pic{height:150px}}\n@media(max-width:480px){.products{grid-template-columns:1fr 1fr;gap:10px}.card-body{padding:12px}.hero-card{padding:22px}.section{padding-top:38px}}\n\n.language-switcher{display:flex;align-items:center;margin-left:auto}\n.language-switcher select{border:1px solid #ddd;border-radius:10px;padding:9px 10px;background:#fff;font-size:14px}\n@media(max-width:700px){.language-switcher select{padding:7px 8px;font-size:13px}}\n\n.searchbar{margin:12px 0 20px}.searchbar input{width:100%;padding:14px 16px;border:1px solid #d7dce5;border-radius:12px;font:inherit}.stock{font-size:13px;margin:7px 0;color:#0f8b4c}.stock.out{color:#b42318}.add:disabled{opacity:.5;cursor:not-allowed}\n",
  "script.js": "let WHATSAPP_NUMBER = \"2290197014571\";\nlet products=[]; let banners=[]; let cart=JSON.parse(localStorage.getItem('bm_cart')||'[]');\nconst money=n=>new Intl.NumberFormat(window.currentLang==='zh'?'zh-CN':'fr-FR').format(n)+' FCFA';\nconst loc=(p,base)=>{const l=window.currentLang;return (l==='en'?p[base+'_en']:l==='zh'?p[base+'_zh']:p[base])||p[base]||''};\nasync function load(){\n  const [pr, ba, st] = await Promise.all([\n    fetch('/api/products').then(r=>r.json()).catch(()=>[]),\n    fetch('/api/banners').then(r=>r.json()).catch(()=>[]),\n    fetch('/api/settings').then(r=>r.json()).catch(()=>({}))\n  ]);\n  products=Array.isArray(pr)?pr:[];\n  banners=Array.isArray(ba)?ba:[];\n  WHATSAPP_NUMBER = st.whatsapp_number || WHATSAPP_NUMBER;\n  renderBanners(); renderProducts(); updateCount();\n}\nfunction img(p){return p.image_key?`<img src=\"${esc(p.image_key)}\" alt=\"${esc(loc(p,'name'))}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:`<span>${p.emoji||'\ud83d\udecd\ufe0f'}</span>`}\nfunction esc(s=''){return String(s).replace(/[&<>\\\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}\nfunction renderBanners(){const el=document.getElementById('bannerWrap');if(!banners.length){el.innerHTML='';return;}const b=banners[0];el.innerHTML=`<div class=\"wrap banner\"><img src=\"${esc(b.image_key)}\" alt=\"${esc(loc(b,'title'))}\"><div class=\"banner-copy\"><h2>${esc(loc(b,'title'))}</h2><p>${esc(loc(b,'subtitle'))}</p>${b.button_link?`<a class=\"primary\" href=\"${esc(b.button_link)}\">${esc(loc(b,'button_text'))}</a>`:''}</div></div>`}\nfunction renderProducts(list=products){document.getElementById('productGrid').innerHTML=list.map(p=>{const out=Number(p.stock)<=0;return `<article class=\"card\"><div class=\"pic\">${img(p)}</div><div class=\"card-body\"><div class=\"tag\">${esc(loc(p,'category'))}</div><h3>${esc(loc(p,'name'))}</h3>${loc(p,'description')?`<p class=\"desc\">${esc(loc(p,'description'))}</p>`:''}<div class=\"price\">${money(p.price)}</div><div class=\"stock ${out?'out':''}\">${out?t('outOfStock'):t('inStock')}: ${Math.max(0,Number(p.stock)||0)}</div><button class=\"add\" ${out?'disabled':''} onclick=\"addToCart(${p.id})\">${out?t('outOfStock'):t('add')}</button></div></article>`}).join('')}\nfunction searchProducts(q){const term=String(q||'').trim().toLowerCase();const list=!term?products:products.filter(p=>[p.name,p.name_en,p.name_zh,p.description,p.description_en,p.description_zh,p.category,p.category_en,p.category_zh].some(v=>String(v||'').toLowerCase().includes(term)));renderProducts(list);document.getElementById('resultLabel').textContent=term?(list.length+' '+t('products')):t('products')}\nfunction filterCat(cat){const list=cat==='Tous'?products:products.filter(p=>p.category===cat||p.category_en===cat||p.category_zh===cat);document.getElementById('resultLabel').textContent=cat==='Tous'?t('products'):cat;renderProducts(list);location.hash='products'}\nfunction addToCart(id){const p=products.find(x=>x.id===id);if(!p||Number(p.stock)<=0)return;const item=cart.find(x=>x.id===id);if(item && item.qty>=Number(p.stock))return;if(item)item.qty++;else cart.push({id,qty:1});save();openCart()}\nfunction save(){localStorage.setItem('bm_cart',JSON.stringify(cart));updateCount()}\nfunction updateCount(){document.getElementById('cartCount').textContent=cart.reduce((a,b)=>a+b.qty,0)}\nfunction openCart(){document.getElementById('cartModal').style.display='flex';renderCart()}\nfunction closeCart(){document.getElementById('cartModal').style.display='none'}\nfunction changeQty(id,d){const item=cart.find(x=>x.id===id);if(!item)return;const p=products.find(x=>x.id===id);item.qty+=d;if(p && item.qty>Number(p.stock))item.qty=Number(p.stock);if(item.qty<=0)cart=cart.filter(x=>x.id!==id);save();renderCart()}\nfunction renderCart(){const box=document.getElementById('cartItems');if(!cart.length){box.innerHTML=`<p style=\"color:#697586\">${t('empty')}</p>`;document.getElementById('cartTotal').textContent='0 FCFA';return}box.innerHTML=cart.map(i=>{const p=products.find(x=>x.id===i.id);if(!p)return '';return `<div class=\"cart-row\"><div class=\"emoji\">${img(p)}</div><div class=\"info\"><b>${esc(loc(p,'name'))}</b><div>${money(p.price)}</div></div><div class=\"qty\"><button onclick=\"changeQty(${p.id},-1)\">\u2212</button> ${i.qty} <button onclick=\"changeQty(${p.id},1)\">+</button></div></div>`}).join('');const total=cart.reduce((s,i)=>{const p=products.find(x=>x.id===i.id);return s+(p?p.price*i.qty:0)},0);document.getElementById('cartTotal').textContent=money(total)}\nfunction checkout(){if(!cart.length){alert(t('empty'));return}let lines=[window.currentLang==='en'?'Hello, I would like to place this order:':window.currentLang==='zh'?'\u60a8\u597d\uff0c\u6211\u60f3\u4e0b\u5355\uff1a':'Bonjour, je voudrais passer cette commande :',''];let total=0;cart.forEach(i=>{const p=products.find(x=>x.id===i.id);if(!p)return;total+=p.price*i.qty;lines.push(`\u2022 ${loc(p,'name')} x${i.qty} \u2014 ${money(p.price*i.qty)}`)});lines.push('',`${t('total')} : ${money(total)}`,'',window.currentLang==='en'?'Please confirm availability and delivery fees.':window.currentLang==='zh'?'\u8bf7\u786e\u8ba4\u5e93\u5b58\u548c\u914d\u9001\u8d39\u7528\u3002':'Merci de confirmer la disponibilit\u00e9 et les frais de livraison.');window.open('https://wa.me/'+WHATSAPP_NUMBER+'?text='+encodeURIComponent(lines.join('\\n')),'_blank')}\nconst oldSetLanguage=window.setLanguage;\nwindow.setLanguage=function(lang){oldSetLanguage(lang);renderBanners();renderProducts();renderCart();};\nload();",
  "i18n.js": "window.I18N = {\n  fr: {\n    label: \"Fran\u00e7ais\", home:\"Accueil\", products:\"Produits\", categories:\"Cat\u00e9gories\", cart:\"Panier\",\n    search:\"Rechercher un produit...\", add:\"Ajouter au panier\", buy:\"Acheter\", empty:\"Votre panier est vide.\",\n    checkout:\"Commander sur WhatsApp\", total:\"Total\", quantity:\"Quantit\u00e9\", price:\"Prix\",\n    admin:\"Administration\", login:\"Connexion\", logout:\"D\u00e9connexion\", save:\"Enregistrer\",\n    cancel:\"Annuler\", edit:\"Modifier\", delete:\"Supprimer\", upload:\"T\u00e9l\u00e9verser\",\n    productName:\"Nom du produit\", description:\"Description\", stock:\"Stock\", category:\"Cat\u00e9gorie\",\n    language:\"Langue\", hero:\"Banni\u00e8re promotionnelle\", close:\"Fermer\", outOfStock:\"Rupture\", inStock:\"En stock\"\n  },\n  en: {\n    label: \"English\", home:\"Home\", products:\"Products\", categories:\"Categories\", cart:\"Cart\",\n    search:\"Search for a product...\", add:\"Add to cart\", buy:\"Buy\", empty:\"Your cart is empty.\",\n    checkout:\"Order on WhatsApp\", total:\"Total\", quantity:\"Quantity\", price:\"Price\",\n    admin:\"Administration\", login:\"Login\", logout:\"Log out\", save:\"Save\",\n    cancel:\"Cancel\", edit:\"Edit\", delete:\"Delete\", upload:\"Upload\",\n    productName:\"Product name\", description:\"Description\", stock:\"Stock\", category:\"Category\",\n    language:\"Language\", hero:\"Promotional banner\", close:\"Close\", outOfStock:\"Out of stock\", inStock:\"In stock\"\n  },\n  zh: {\n    label: \"\u4e2d\u6587\", home:\"\u9996\u9875\", products:\"\u5546\u54c1\", categories:\"\u5206\u7c7b\", cart:\"\u8d2d\u7269\u8f66\",\n    search:\"\u641c\u7d22\u5546\u54c1...\", add:\"\u52a0\u5165\u8d2d\u7269\u8f66\", buy:\"\u7acb\u5373\u8d2d\u4e70\", empty:\"\u8d2d\u7269\u8f66\u662f\u7a7a\u7684\u3002\",\n    checkout:\"\u901a\u8fc7 WhatsApp \u4e0b\u5355\", total:\"\u5408\u8ba1\", quantity:\"\u6570\u91cf\", price:\"\u4ef7\u683c\",\n    admin:\"\u7ba1\u7406\u540e\u53f0\", login:\"\u767b\u5f55\", logout:\"\u9000\u51fa\u767b\u5f55\", save:\"\u4fdd\u5b58\",\n    cancel:\"\u53d6\u6d88\", edit:\"\u7f16\u8f91\", delete:\"\u5220\u9664\", upload:\"\u4e0a\u4f20\",\n    productName:\"\u5546\u54c1\u540d\u79f0\", description:\"\u5546\u54c1\u63cf\u8ff0\", stock:\"\u5e93\u5b58\", category:\"\u5206\u7c7b\",\n    language:\"\u8bed\u8a00\", hero:\"\u9996\u9875\u5ba3\u4f20\u56fe\", close:\"\u5173\u95ed\", outOfStock:\"\u7f3a\u8d27\", inStock:\"\u6709\u5e93\u5b58\"\n  }\n};\n\nwindow.currentLang = localStorage.getItem(\"siteLanguage\") || \"fr\";\nwindow.t = function(key) {\n  return (window.I18N[window.currentLang] && window.I18N[window.currentLang][key]) ||\n         (window.I18N.fr[key]) || key;\n};\nwindow.setLanguage = function(lang) {\n  if (!window.I18N[lang]) return;\n  window.currentLang = lang;\n  localStorage.setItem(\"siteLanguage\", lang);\n  document.documentElement.lang = lang;\n  document.querySelectorAll(\"[data-i18n]\").forEach(el => {\n    const key = el.dataset.i18n;\n    el.textContent = window.t(key);\n  });\n  document.querySelectorAll(\"[data-i18n-placeholder]\").forEach(el => {\n    el.placeholder = window.t(el.dataset.i18nPlaceholder);\n  });\n  const select = document.querySelector(\"#languageSelect\");\n  if (select) select.value = lang;\n};\ndocument.addEventListener(\"DOMContentLoaded\", () => window.setLanguage(window.currentLang));",
  "admin/index.html": "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Benin Market \u2014 Administration</title><style>\n*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;background:#f5f7fb;color:#172033}.wrap{max-width:1100px;margin:auto;padding:20px}.top{background:#fff;border-bottom:1px solid #e5e7eb;position:sticky;top:0;z-index:5}.topin{display:flex;align-items:center;justify-content:space-between;gap:12px}.brand{font-weight:800;font-size:20px}.brand span{display:inline-grid;place-items:center;background:#0f8b4c;color:#fff;border-radius:10px;width:36px;height:36px;margin-right:8px}.btn{border:0;border-radius:10px;padding:11px 15px;font-weight:700;cursor:pointer}.primary{background:#0f8b4c;color:#fff}.danger{background:#ffe7e7;color:#b42318}.ghost{background:#eef2f7}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.panel{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:18px;box-shadow:0 5px 18px rgba(16,24,40,.04)}label{display:block;font-weight:700;margin:12px 0 6px}input,textarea,select{width:100%;padding:11px;border:1px solid #d7dce5;border-radius:10px;font:inherit}textarea{min-height:90px;resize:vertical}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.upload{border:2px dashed #ccd3dd;border-radius:12px;padding:18px;text-align:center}.preview{max-width:100%;max-height:180px;border-radius:10px;margin-top:10px}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:10px;border-bottom:1px solid #eee;text-align:left;vertical-align:top}.thumb{width:64px;height:64px;object-fit:cover;border-radius:8px;background:#f2f4f7}.login{max-width:420px;margin:90px auto}.muted{color:#667085}.hidden{display:none!important}.tabs{display:flex;gap:8px;margin:20px 0;flex-wrap:wrap}.tab.active{background:#172033;color:#fff}.notice{padding:12px;border-radius:10px;background:#eef7f1;margin-bottom:15px}.actions{display:flex;gap:8px;flex-wrap:wrap}@media(max-width:800px){.grid{grid-template-columns:1fr}.row{grid-template-columns:1fr}.table{font-size:13px}.table th:nth-child(2),.table td:nth-child(2){display:none}}\n.langbox{margin-top:14px;padding:12px;border-radius:12px;background:#f8fafc;border:1px solid #e5e7eb}.langbox label{font-size:13px}</style></head><body>\n<header class=\"top\"><div class=\"wrap topin\"><div class=\"brand\"><span>BM</span>Benin Market \u2014 Administration</div><div><select id=\"adminLanguage\" onchange=\"localStorage.setItem('adminLanguage',this.value)\" style=\"width:auto;margin-right:8px\"><option value=\"fr\">\ud83c\uddeb\ud83c\uddf7 FR</option><option value=\"en\">\ud83c\uddec\ud83c\udde7 EN</option><option value=\"zh\">\ud83c\udde8\ud83c\uddf3 \u4e2d\u6587</option></select><div id=\"topActions\" class=\"hidden\"><a class=\"btn ghost\" href=\"/\" target=\"_blank\">Voir le site</a> <button class=\"btn danger\" onclick=\"logout()\">D\u00e9connexion</button></div></div></header>\n<div id=\"login\" class=\"wrap login\"><div class=\"panel\"><h1>Connexion propri\u00e9taire</h1><p class=\"muted\">Cette zone est r\u00e9serv\u00e9e \u00e0 l\u2019administrateur.</p><label>Mot de passe</label><input id=\"password\" type=\"password\" autocomplete=\"current-password\"><button class=\"btn primary\" style=\"width:100%;margin-top:14px\" onclick=\"login()\">Se connecter</button><p id=\"loginMsg\" class=\"muted\"></p></div></div>\n<main id=\"app\" class=\"wrap hidden\"><div class=\"notice\">Vous \u00eates dans le panneau de contr\u00f4le. Les produits et les images sont enregistr\u00e9s c\u00f4t\u00e9 serveur, pas dans le code visible par les clients.</div><div class=\"tabs\"><button class=\"btn tab active\" onclick=\"showTab('products',this)\">\ud83d\udce6 Produits</button><button class=\"btn tab\" onclick=\"showTab('banners',this)\">\ud83d\uddbc\ufe0f Promotions / affiches</button><button class=\"btn tab\" onclick=\"showTab('settings',this)\">\u2699\ufe0f Param\u00e8tres</button></div>\n<section id=\"products\" class=\"grid\"><div class=\"panel\"><h2 id=\"pTitle\">Ajouter un produit</h2><input type=\"hidden\" id=\"pid\"><label>Nom du produit</label><input id=\"pname\" placeholder=\"Ex. Riz parfum\u00e9\"><label>Description</label><textarea id=\"pdesc\" placeholder=\"D\u00e9crivez le produit...\"></textarea><div class=\"langbox\"><b>\ud83c\udf10 Traductions du produit</b><div class=\"row\"><div><label>English \u2014 nom</label><input id=\"pname_en\" placeholder=\"Product name\"></div><div><label>\u4e2d\u6587 \u2014 \u540d\u79f0</label><input id=\"pname_zh\" placeholder=\"\u5546\u54c1\u540d\u79f0\"></div></div><div class=\"row\"><div><label>English \u2014 description</label><textarea id=\"pdesc_en\" placeholder=\"Product description\"></textarea></div><div><label>\u4e2d\u6587 \u2014 \u63cf\u8ff0</label><textarea id=\"pdesc_zh\" placeholder=\"\u5546\u54c1\u63cf\u8ff0\"></textarea></div></div></div><div class=\"row\"><div><label>Prix (FCFA)</label><input id=\"pprice\" type=\"number\" min=\"0\"></div><div><label>Stock</label><input id=\"pstock\" type=\"number\" min=\"0\"></div></div><div class=\"row\"><div><label>Cat\u00e9gorie</label><input id=\"pcat\" list=\"cats\" placeholder=\"Maison\"><input id=\"pcat_en\" placeholder=\"Category in English\" style=\"margin-top:6px\"><input id=\"pcat_zh\" placeholder=\"\u4e2d\u6587\u5206\u7c7b\" style=\"margin-top:6px\"><datalist id=\"cats\"><option>Maison</option><option>Cuisine</option><option>\u00c9lectronique</option><option>Beaut\u00e9</option></datalist></div><div><label>Emoji (si pas d\u2019image)</label><input id=\"pemoji\" value=\"\ud83d\udecd\ufe0f\"></div></div><label>\u56fe\u7247\u94fe\u63a5 / Image URL</label><input id=\"pimage\" placeholder=\"https://.../image.jpg\"><div class=\"muted\" style=\"margin-top:6px\">\u8bf7\u5148\u628a\u56fe\u7247\u653e\u5230\u56fe\u7247\u6258\u7ba1\u670d\u52a1\uff0c\u7136\u540e\u7c98\u8d34 https:// \u5f00\u5934\u7684\u56fe\u7247\u94fe\u63a5\u3002\u4e5f\u53ef\u4ee5\u6682\u65f6\u7559\u7a7a\u4f7f\u7528 Emoji\u3002</div><img id=\"pimg\" class=\"preview hidden\"><div class=\"actions\" style=\"margin-top:14px\"><button class=\"btn primary\" onclick=\"saveProduct()\">\ud83d\udcbe Enregistrer</button><button class=\"btn ghost\" onclick=\"resetProduct()\">Nouveau</button></div></div><div class=\"panel\"><h2>Mes produits</h2><div id=\"productList\">Chargement...</div></div></section>\n<section id=\"banners\" class=\"grid hidden\"><div class=\"panel\"><h2 id=\"bTitle\">Ajouter une affiche promotionnelle</h2><input type=\"hidden\" id=\"bid\"><label>\u56fe\u7247\u94fe\u63a5 / Image URL</label><input id=\"bimage\" placeholder=\"https://.../banner.jpg\"><div class=\"muted\" style=\"margin-top:6px\">\u8bf7\u7c98\u8d34\u5ba3\u4f20\u56fe\u7247\u7684 https:// \u56fe\u7247\u94fe\u63a5\u3002</div><img id=\"bimg\" class=\"preview hidden\"><label>Titre</label><input id=\"btitle\" placeholder=\"Grande promotion\"><label>Sous-titre</label><textarea id=\"bsubtitle\" placeholder=\"Profitez de nos offres...\"></textarea>\n<div class=\"langbox\"><b>\ud83c\udf10 Traductions de la promotion</b><div class=\"row\"><div><label>English \u2014 title</label><input id=\"btitle_en\" placeholder=\"Big promotion\"></div><div><label>\u4e2d\u6587 \u2014 \u6807\u9898</label><input id=\"btitle_zh\" placeholder=\"\u5927\u4fc3\u9500\"></div></div><div class=\"row\"><div><label>English \u2014 subtitle</label><textarea id=\"bsubtitle_en\" placeholder=\"Enjoy our special offers...\"></textarea></div><div><label>\u4e2d\u6587 \u2014 \u526f\u6807\u9898</label><textarea id=\"bsubtitle_zh\" placeholder=\"\u6b22\u8fce\u4eab\u53d7\u4f18\u60e0...\"></textarea></div></div></div><div class=\"row\"><div><label>Texte du bouton</label><input id=\"bbutton\" value=\"Voir les produits\"><input id=\"bbutton_en\" value=\"View products\" style=\"margin-top:6px\"><input id=\"bbutton_zh\" value=\"\u67e5\u770b\u5546\u54c1\" style=\"margin-top:6px\"></div><div><label>Lien du bouton</label><input id=\"blink\" value=\"#products\"></div></div><div class=\"row\"><div><label>Ordre</label><input id=\"border\" type=\"number\" value=\"0\"></div><div></div></div><div class=\"actions\" style=\"margin-top:14px\"><button class=\"btn primary\" onclick=\"saveBanner()\">\ud83d\udcbe Enregistrer</button><button class=\"btn ghost\" onclick=\"resetBanner()\">Nouveau</button></div></div><div class=\"panel\"><h2>Mes affiches</h2><div id=\"bannerList\">Chargement...</div></div></section><section id=\"settings\" class=\"grid hidden\"><div class=\"panel\"><h2>Param\u00e8tres de la boutique</h2><label>Nom de la boutique</label><input id=\"storeName\" value=\"BENIN SHOP\"><label>Num\u00e9ro WhatsApp</label><input id=\"whatsapp\" value=\"0197014571\" inputmode=\"tel\" placeholder=\"0197014571\"><p class=\"muted\">Utilisez le num\u00e9ro b\u00e9ninois complet. Le site convertit automatiquement le num\u00e9ro au format WhatsApp international.</p><button class=\"btn primary\" onclick=\"saveSettings()\">\ud83d\udcbe Enregistrer</button></div><div class=\"panel\"><h2>Acc\u00e8s</h2><p>Cette zone est r\u00e9serv\u00e9e \u00e0 l\u2019administrateur. Le mot de passe est conserv\u00e9 comme Secret dans Cloudflare et n\u2019est jamais affich\u00e9 dans le site.</p></div></section>\n</main><script src=\"admin.js\"></script></body></html>\n",
  "admin/admin.js": "let editingProduct=null, editingBanner=null;\nconst $=id=>document.getElementById(id);\nasync function api(url,opt={}){const r=await fetch(url,opt);let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||'Erreur');return d}\nasync function boot(){try{const m=await api('/api/admin/me');if(m.authenticated)showApp();else $('login').classList.remove('hidden')}catch{$('login').classList.remove('hidden')}}\nasync function login(){try{await api('/api/admin/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:$('password').value})});showApp()}catch(e){$('loginMsg').textContent=e.message}}\nasync function logout(){await api('/api/admin/logout',{method:'POST'});location.reload()}\nfunction showApp(){$('login').classList.add('hidden');$('app').classList.remove('hidden');$('topActions').classList.remove('hidden');loadProducts();loadBanners();loadSettings()}\nfunction showTab(id,btn){document.querySelectorAll('#app>section').forEach(x=>x.classList.add('hidden'));$(id).classList.remove('hidden');document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));btn.classList.add('active')}\nasync function loadProducts(){const a=await api('/api/admin/products');$('productList').innerHTML=a.length?`<table class=\"table\"><tr><th>\u56fe\u7247</th><th>\u540d\u79f0</th><th>\u4ef7\u683c</th><th>\u5e93\u5b58</th><th>\u64cd\u4f5c</th></tr>${a.map(p=>`<tr><td>${p.image_key?`<img class=\"thumb\" src=\"${esc(p.image_key)}\">`:p.emoji||'\ud83d\udecd\ufe0f'}</td><td><b>${esc(p.name)}</b><br><span class=\"muted\">${esc(p.category)}</span></td><td>${money(p.price)}</td><td>${p.stock}</td><td><div class=\"actions\"><button class=\"btn ghost\" onclick='editProduct(${JSON.stringify(p)})'>\u7f16\u8f91</button><button class=\"btn danger\" onclick=\"deleteProduct(${p.id})\">\u5220\u9664</button></div></td></tr>`).join('')}</table>`:'\u6682\u65e0\u4ea7\u54c1\u3002'}\nfunction editProduct(p){editingProduct=p;$('pTitle').textContent='\u7f16\u8f91\u4ea7\u54c1';$('pid').value=p.id;$('pname').value=p.name;$('pname_en').value=p.name_en||'';$('pname_zh').value=p.name_zh||'';$('pdesc').value=p.description||'';$('pdesc_en').value=p.description_en||'';$('pdesc_zh').value=p.description_zh||'';$('pprice').value=p.price;$('pstock').value=p.stock;$('pcat').value=p.category;$('pcat_en').value=p.category_en||'';$('pcat_zh').value=p.category_zh||'';$('pemoji').value=p.emoji||'\ud83d\udecd\ufe0f';$('pimage').value=p.image_key||'';if(p.image_key){$('pimg').src=p.image_key;$('pimg').classList.remove('hidden')}}\nasync function saveProduct(){try{const b={name:$('pname').value.trim(),name_en:$('pname_en').value.trim(),name_zh:$('pname_zh').value.trim(),description:$('pdesc').value,description_en:$('pdesc_en').value,description_zh:$('pdesc_zh').value,price:Number($('pprice').value),stock:Number($('pstock').value),category:$('pcat').value||'Maison',category_en:$('pcat_en').value.trim(),category_zh:$('pcat_zh').value.trim(),emoji:$('pemoji').value||'\ud83d\udecd\ufe0f',image_key:$('pimage').value,active:true};if(!b.name)throw Error('\u8bf7\u586b\u5199\u5546\u54c1\u540d\u79f0');if($('pid').value)await api('/api/admin/products/'+$('pid').value,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(b)});else await api('/api/admin/products',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});resetProduct();loadProducts();alert('\u4fdd\u5b58\u6210\u529f')}catch(e){alert(e.message)}}\nasync function deleteProduct(id){if(!confirm('\u786e\u5b9a\u5220\u9664\u8fd9\u4e2a\u5546\u54c1\u5417\uff1f'))return;await api('/api/admin/products/'+id,{method:'DELETE'});loadProducts()}\nfunction resetProduct(){editingProduct=null;$('pTitle').textContent='Ajouter un produit';['pid','pname','pname_en','pname_zh','pdesc','pdesc_en','pdesc_zh','pprice','pstock','pcat','pcat_en','pcat_zh','pimage'].forEach(x=>$(x).value='');$('pemoji').value='\ud83d\udecd\ufe0f';$('pimg').classList.add('hidden')}\nasync function loadBanners(){const a=await api('/api/admin/banners');$('bannerList').innerHTML=a.length?`<table class=\"table\"><tr><th>\u56fe\u7247</th><th>\u5185\u5bb9</th><th>\u72b6\u6001</th><th>\u64cd\u4f5c</th></tr>${a.map(b=>`<tr><td><img class=\"thumb\" src=\"${esc(b.image_key)}\"></td><td><b>${esc(b.title)}</b><br>${esc(b.subtitle)}</td><td>${b.active?'\u663e\u793a':'\u9690\u85cf'}</td><td><div class=\"actions\"><button class=\"btn ghost\" onclick='editBanner(${JSON.stringify(b)})'>\u7f16\u8f91</button><button class=\"btn danger\" onclick=\"deleteBanner(${b.id})\">\u5220\u9664</button></div></td></tr>`).join('')}</table>`:'\u6682\u65e0\u5ba3\u4f20\u56fe\u3002'}\nfunction editBanner(b){editingBanner=b;$('bTitle').textContent='\u7f16\u8f91\u5ba3\u4f20\u56fe';$('bid').value=b.id;$('bimage').value=b.image_key;$('btitle').value=b.title||'';$('btitle_en').value=b.title_en||'';$('btitle_zh').value=b.title_zh||'';$('bsubtitle').value=b.subtitle||'';$('bsubtitle_en').value=b.subtitle_en||'';$('bsubtitle_zh').value=b.subtitle_zh||'';$('bbutton').value=b.button_text||'Voir les produits';$('bbutton_en').value=b.button_text_en||'View products';$('bbutton_zh').value=b.button_text_zh||'\u67e5\u770b\u5546\u54c1';$('blink').value=b.button_link||'#products';$('border').value=b.sort_order||0;$('bimg').src=b.image_key;$('bimg').classList.remove('hidden')}\nasync function saveBanner(){try{const b={image_key:$('bimage').value,title:$('btitle').value,title_en:$('btitle_en').value,title_zh:$('btitle_zh').value,subtitle:$('bsubtitle').value,subtitle_en:$('bsubtitle_en').value,subtitle_zh:$('bsubtitle_zh').value,button_text:$('bbutton').value,button_text_en:$('bbutton_en').value,button_text_zh:$('bbutton_zh').value,button_link:$('blink').value,sort_order:Number($('border').value)||0,active:true};if(!/^https?:\\/\\//i.test(b.image_key))throw Error('\u8bf7\u586b\u5199\u6709\u6548\u7684\u56fe\u7247\u94fe\u63a5\uff08http:// \u6216 https://\uff09');if($('bid').value)await api('/api/admin/banners/'+$('bid').value,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(b)});else await api('/api/admin/banners',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});resetBanner();loadBanners();alert('\u4fdd\u5b58\u6210\u529f')}catch(e){alert(e.message)}}\nasync function deleteBanner(id){if(!confirm('\u786e\u5b9a\u5220\u9664\u8fd9\u5f20\u5ba3\u4f20\u56fe\u5417\uff1f'))return;await api('/api/admin/banners/'+id,{method:'DELETE'});loadBanners()}\nfunction resetBanner(){editingBanner=null;$('bTitle').textContent='Ajouter une affiche promotionnelle';['bid','bimage','btitle','bsubtitle','blink'].forEach(x=>$(x).value='');$('btitle_en').value='';$('btitle_zh').value='';$('bsubtitle_en').value='';$('bsubtitle_zh').value='';$('bbutton').value='Voir les produits';$('bbutton_en').value='View products';$('bbutton_zh').value='\u67e5\u770b\u5546\u54c1';$('border').value='0';$('bimg').classList.add('hidden')}\nfunction money(n){return new Intl.NumberFormat('fr-FR').format(n)+' FCFA'}\nfunction esc(s=''){return s.replace(/[&<>\\\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}\nboot();\n\nasync function loadSettings(){try{const s=await api('/api/admin/settings');$('whatsapp').value=s.whatsapp_number||'0197014571';$('storeName').value=s.store_name||'BENIN SHOP'}catch(e){}}\nasync function saveSettings(){try{await api('/api/admin/settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({whatsapp_number:$('whatsapp').value,store_name:$('storeName').value})});alert('\u8bbe\u7f6e\u5df2\u4fdd\u5b58')}catch(e){alert(e.message)}}\n",
};

const CONTENT_TYPES = {
  'html': 'text/html; charset=utf-8',
  'css': 'text/css; charset=utf-8',
  'js': 'application/javascript; charset=utf-8',
};

function staticResponse(path) {
  let key = path.replace(/^\/+/, '');
  if (!key || key === 'admin') key = key === 'admin' ? 'admin/index.html' : 'index.html';
  if (key === 'admin/') key = 'admin/index.html';
  const body = STATIC_FILES[key];
  if (body == null) return new Response('Not found', { status: 404 });
  const ext = key.split('.').pop();
  return new Response(body, { headers: { 'content-type': CONTENT_TYPES[ext] || 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=300' } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return handleApi(request, env);
    return staticResponse(url.pathname);
  }
};

