import { Hono } from 'hono'
import { serveStatic } from 'hono/cloudflare-workers'
import { cors } from 'hono/cors'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────
type Bindings = {
  SUPABASE_URL: string
  SUPABASE_ANON_KEY: string
  SUPABASE_SERVICE_ROLE_KEY: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/static/*', serveStatic({ root: './' }))
app.use('/api/*', cors())

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS SUPABASE
// ─────────────────────────────────────────────────────────────────────────────
async function supabaseAuth(url: string, anonKey: string, body: object) {
  const res = await fetch(`${url}/auth/v1/${Object.keys(body)[0] === 'email' ? 'signup' : 'token?grant_type=password'}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': anonKey,
      'Authorization': `Bearer ${anonKey}`,
    },
    body: JSON.stringify(body),
  })
  return res
}

async function supabaseSignup(url: string, anonKey: string, serviceKey: string, email: string, password: string, metadata: object) {
  const res = await fetch(`${url}/auth/v1/signup`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
    },
    body: JSON.stringify({ email, password, data: metadata }),
  })
  return res
}

async function supabaseSignin(url: string, anonKey: string, email: string, password: string) {
  const res = await fetch(`${url}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': anonKey,
      'Authorization': `Bearer ${anonKey}`,
    },
    body: JSON.stringify({ email, password }),
  })
  return res
}

async function supabaseGetUser(url: string, anonKey: string, token: string) {
  const res = await fetch(`${url}/auth/v1/user`, {
    headers: {
      'apikey': anonKey,
      'Authorization': `Bearer ${token}`,
    },
  })
  return res
}

async function supabaseCreateProfile(url: string, serviceKey: string, profile: object) {
  const res = await fetch(`${url}/rest/v1/profiles`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
      'Prefer': 'return=minimal',
    },
    body: JSON.stringify(profile),
  })
  return res
}

async function supabaseGetProfile(url: string, serviceKey: string, userId: string) {
  const res = await fetch(`${url}/rest/v1/profiles?id=eq.${userId}&select=*`, {
    headers: {
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
    },
  })
  return res
}

// Middleware: vérifie le cookie de session
async function requireAuth(c: any, next: any) {
  const token = getCookie(c, 'sb_token')
  if (!token) return c.redirect('/login?msg=session_expired')
  const supaUrl = c.env?.SUPABASE_URL || ''
  const supaKey = c.env?.SUPABASE_ANON_KEY || ''
  if (supaUrl) {
    const userRes = await supabaseGetUser(supaUrl, supaKey, token)
    if (!userRes.ok) {
      deleteCookie(c, 'sb_token')
      return c.redirect('/login?msg=session_expired')
    }
  }
  await next()
}

// ─────────────────────────────────────────────────────────────────────────────
// API ROUTES — AUTH
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (c) => {
  try {
    const body = await c.req.json()
    const { email, password, full_name, phone, role, country, whatsapp_number, is_diaspora } = body

    if (!email || !password || !full_name || !phone) {
      return c.json({ error: 'Champs obligatoires manquants' }, 400)
    }
    if (password.length < 8) {
      return c.json({ error: 'Le mot de passe doit contenir au moins 8 caractères' }, 400)
    }

    const supaUrl = c.env.SUPABASE_URL
    const supaKey = c.env.SUPABASE_ANON_KEY
    const serviceKey = c.env.SUPABASE_SERVICE_ROLE_KEY

    if (!supaUrl || supaUrl === 'YOUR_SUPABASE_URL') {
      // Mode démo sans Supabase configuré
      const fakeToken = btoa(JSON.stringify({ id: crypto.randomUUID(), email, full_name, role: role || 'owner' }))
      setCookie(c, 'sb_token', fakeToken, { httpOnly: true, path: '/', maxAge: 86400 * 7, sameSite: 'Lax' })
      setCookie(c, 'user_name', full_name, { path: '/', maxAge: 86400 * 7 })
      setCookie(c, 'user_email', email, { path: '/', maxAge: 86400 * 7 })
      setCookie(c, 'user_role', role || 'owner', { path: '/', maxAge: 86400 * 7 })
      return c.json({ success: true, message: 'Compte créé (mode démo)', redirect: '/dashboard' })
    }

    // Créer l'utilisateur dans Supabase Auth
    const signupRes = await supabaseSignup(supaUrl, supaKey, serviceKey, email, password, {
      full_name, phone, role: role || 'owner'
    })
    const signupData = await signupRes.json() as any

    if (!signupRes.ok || signupData.error) {
      const msg = signupData.msg || signupData.error_description || signupData.error || 'Erreur lors de la création du compte'
      if (msg.toLowerCase().includes('already registered') || msg.toLowerCase().includes('already been registered')) {
        return c.json({ error: 'Cet email est déjà utilisé. Veuillez vous connecter.' }, 409)
      }
      return c.json({ error: msg }, 400)
    }

    const userId = signupData.user?.id || signupData.id
    if (!userId) return c.json({ error: 'Erreur serveur: ID utilisateur manquant' }, 500)

    // Créer le profil dans la table profiles
    await supabaseCreateProfile(supaUrl, serviceKey, {
      id: userId,
      full_name,
      phone,
      role: role || 'owner',
      country: country || 'BF',
      whatsapp_number: whatsapp_number || phone,
      is_diaspora: is_diaspora || false,
    })

    // Connecter automatiquement après inscription
    const signinRes = await supabaseSignin(supaUrl, supaKey, email, password)
    const signinData = await signinRes.json() as any

    if (signinRes.ok && signinData.access_token) {
      setCookie(c, 'sb_token', signinData.access_token, { httpOnly: true, path: '/', maxAge: 86400 * 7, sameSite: 'Lax' })
      setCookie(c, 'user_name', full_name, { path: '/', maxAge: 86400 * 7 })
      setCookie(c, 'user_email', email, { path: '/', maxAge: 86400 * 7 })
      setCookie(c, 'user_role', role || 'owner', { path: '/', maxAge: 86400 * 7 })
    }

    return c.json({ success: true, message: 'Compte créé avec succès !', redirect: '/dashboard' })
  } catch (err: any) {
    return c.json({ error: 'Erreur serveur: ' + (err.message || 'inconnue') }, 500)
  }
})

// POST /api/auth/login
app.post('/api/auth/login', async (c) => {
  try {
    const body = await c.req.json()
    const { email, password } = body

    if (!email || !password) {
      return c.json({ error: 'Email et mot de passe requis' }, 400)
    }

    const supaUrl = c.env.SUPABASE_URL
    const supaKey = c.env.SUPABASE_ANON_KEY
    const serviceKey = c.env.SUPABASE_SERVICE_ROLE_KEY

    if (!supaUrl || supaUrl === 'YOUR_SUPABASE_URL') {
      // Mode démo
      if (password.length < 3) return c.json({ error: 'Identifiants incorrects' }, 401)
      const demoName = email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())
      const fakeToken = btoa(JSON.stringify({ id: crypto.randomUUID(), email, full_name: demoName, role: 'owner' }))
      setCookie(c, 'sb_token', fakeToken, { httpOnly: true, path: '/', maxAge: 86400 * 7, sameSite: 'Lax' })
      setCookie(c, 'user_name', demoName, { path: '/', maxAge: 86400 * 7 })
      setCookie(c, 'user_email', email, { path: '/', maxAge: 86400 * 7 })
      setCookie(c, 'user_role', 'owner', { path: '/', maxAge: 86400 * 7 })
      return c.json({ success: true, redirect: '/dashboard' })
    }

    const res = await supabaseSignin(supaUrl, supaKey, email, password)
    const data = await res.json() as any

    if (!res.ok || data.error) {
      const msg = data.error_description || data.error || data.msg || 'Identifiants incorrects'
      if (msg.toLowerCase().includes('invalid') || msg.toLowerCase().includes('not found')) {
        return c.json({ error: 'Email ou mot de passe incorrect' }, 401)
      }
      return c.json({ error: msg }, 401)
    }

    const token = data.access_token
    if (!token) return c.json({ error: 'Erreur d\'authentification' }, 500)

    // Récupérer le profil
    let displayName = email.split('@')[0]
    let userRole = 'owner'
    if (data.user?.id) {
      const profRes = await supabaseGetProfile(supaUrl, serviceKey, data.user.id)
      if (profRes.ok) {
        const profiles = await profRes.json() as any[]
        if (profiles?.[0]) {
          displayName = profiles[0].full_name || displayName
          userRole = profiles[0].role || 'owner'
        }
      }
    }

    setCookie(c, 'sb_token', token, { httpOnly: true, path: '/', maxAge: 86400 * 7, sameSite: 'Lax' })
    setCookie(c, 'user_name', displayName, { path: '/', maxAge: 86400 * 7 })
    setCookie(c, 'user_email', email, { path: '/', maxAge: 86400 * 7 })
    setCookie(c, 'user_role', userRole, { path: '/', maxAge: 86400 * 7 })

    return c.json({ success: true, redirect: '/dashboard' })
  } catch (err: any) {
    return c.json({ error: 'Erreur serveur: ' + (err.message || 'inconnue') }, 500)
  }
})

// POST /api/auth/logout
app.post('/api/auth/logout', async (c) => {
  deleteCookie(c, 'sb_token', { path: '/' })
  deleteCookie(c, 'user_name', { path: '/' })
  deleteCookie(c, 'user_email', { path: '/' })
  deleteCookie(c, 'user_role', { path: '/' })
  return c.json({ success: true, redirect: '/login' })
})

// GET /api/auth/me
app.get('/api/auth/me', async (c) => {
  const token = getCookie(c, 'sb_token')
  const name = getCookie(c, 'user_name')
  const email = getCookie(c, 'user_email')
  const role = getCookie(c, 'user_role')
  if (!token) return c.json({ authenticated: false }, 401)
  return c.json({ authenticated: true, name, email, role })
})

// ─────────────────────────────────────────────────────────────────────────────
// API ROUTES — DATA (protégées)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/stats', requireAuth, (c) => c.json({
  totalChantiers: 12, chantiersActifs: 7,
  budgetTotal: 145000000, budgetConsomme: 89200000,
  alertesEnAttente: 3, livraisons: 48, risqueScore: 24
}))

app.get('/api/chantiers', requireAuth, (c) => c.json([
  { id: 1, name: 'Villa Familiale — Zone 1', location: 'Ouagadougou', progress: 68, budget: 45000000, spent: 30600000, risk: 15, status: 'active' },
  { id: 2, name: 'Maison R+1 — Pissy', location: 'Ouagadougou', progress: 35, budget: 28000000, spent: 9800000, risk: 42, status: 'active' },
  { id: 3, name: 'Villa Bobo-Dioulasso', location: 'Bobo-Dioulasso', progress: 20, budget: 54000000, spent: 10800000, risk: 71, status: 'active' },
]))

// ─────────────────────────────────────────────────────────────────────────────
// PAGES — Routes HTML
// ─────────────────────────────────────────────────────────────────────────────
app.get('/', (c) => c.redirect('/login'))

app.get('/login', (c) => {
  const token = getCookie(c, 'sb_token')
  if (token) return c.redirect('/dashboard')
  const msg = c.req.query('msg') || ''
  const err = c.req.query('error') || ''
  return c.html(loginPage(msg, err))
})

app.get('/register', (c) => {
  const token = getCookie(c, 'sb_token')
  if (token) return c.redirect('/dashboard')
  return c.html(registerPage())
})

app.get('/logout', async (c) => {
  deleteCookie(c, 'sb_token', { path: '/' })
  deleteCookie(c, 'user_name', { path: '/' })
  deleteCookie(c, 'user_email', { path: '/' })
  deleteCookie(c, 'user_role', { path: '/' })
  return c.redirect('/login?msg=logged_out')
})

// Routes protégées
app.get('/dashboard', requireAuth, (c) => {
  const name = getCookie(c, 'user_name') || 'Utilisateur'
  const role = getCookie(c, 'user_role') || 'owner'
  return c.html(dashboardPage(name, role))
})
app.get('/chantiers', requireAuth, (c) => c.html(chantiersPage()))
app.get('/chantier/:id', requireAuth, (c) => c.html(chantierDetailPage(c.req.param('id'))))
app.get('/budget', requireAuth, (c) => c.html(budgetPage()))
app.get('/approvisionnements', requireAuth, (c) => c.html(approvPage()))
app.get('/materiaux', requireAuth, (c) => c.html(materiauxPage()))
app.get('/journal', requireAuth, (c) => c.html(journalPage()))
app.get('/alertes', requireAuth, (c) => c.html(alertesPage()))
app.get('/rapports', requireAuth, (c) => c.html(rapportsPage()))
app.get('/abonnements', requireAuth, (c) => c.html(abonnementsPage()))
app.get('/admin', requireAuth, (c) => c.html(adminPage()))
app.get('/profil', requireAuth, (c) => {
  const name = getCookie(c, 'user_name') || ''
  const email = getCookie(c, 'user_email') || ''
  const role = getCookie(c, 'user_role') || ''
  return c.html(profilPage(name, email, role))
})

// ─────────────────────────────────────────────────────────────────────────────
// HTML SHELL
// ─────────────────────────────────────────────────────────────────────────────
function shell(title: string, body: string) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>${title} — FasoChantier</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    theme: {
      extend: {
        colors: {
          brand: { 400:'#fb923c', 500:'#f97316', 600:'#ea580c', 700:'#c2410c' },
          dark:  { 900:'#0f1117', 800:'#13161f', 700:'#1a1f2e', 600:'#1e2538', 500:'#252d3d' }
        },
        fontFamily: { sans: ['Inter','system-ui','sans-serif'] }
      }
    }
  }
</script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet"/>
<link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet"/>
<style>
*{box-sizing:border-box}
:root{--sw:260px}
body{font-family:'Inter',sans-serif;background:#0f1117;color:#e2e8f0;overflow-x:hidden}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:#1a1f2e}
::-webkit-scrollbar-thumb{background:#f97316;border-radius:3px}
.sidebar{width:var(--sw);background:linear-gradient(180deg,#13161f,#0f1117);border-right:1px solid rgba(249,115,22,.1);position:fixed;top:0;left:0;bottom:0;overflow-y:auto;z-index:50;transition:transform .3s}
.main-content{margin-left:var(--sw);min-height:100vh}
.nav-item{display:flex;align-items:center;gap:12px;padding:9px 14px;border-radius:10px;color:#94a3b8;text-decoration:none;font-size:14px;font-weight:500;transition:all .2s;margin-bottom:2px}
.nav-item:hover,.nav-item.active{background:rgba(249,115,22,.12);color:#fb923c}
.nav-item.active{border:1px solid rgba(249,115,22,.2)}
.nav-icon{width:32px;height:32px;display:flex;align-items:center;justify-content:center;border-radius:8px;font-size:13px;flex-shrink:0}
.nav-item.active .nav-icon{background:rgba(249,115,22,.2);color:#f97316}
.topbar{background:rgba(15,17,23,.95);border-bottom:1px solid rgba(255,255,255,.06);backdrop-filter:blur(20px);position:sticky;top:0;z-index:40}
.card{background:linear-gradient(145deg,#1a1f2e,#161b27);border:1px solid rgba(255,255,255,.06);border-radius:16px;transition:all .25s}
.card:hover{border-color:rgba(249,115,22,.18);transform:translateY(-1px);box-shadow:0 8px 32px rgba(0,0,0,.3)}
.btn-primary{background:linear-gradient(135deg,#ea580c,#f97316);color:#fff;border:none;padding:10px 22px;border-radius:10px;font-weight:600;font-size:14px;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px;text-decoration:none}
.btn-primary:hover{background:linear-gradient(135deg,#c2410c,#ea580c);transform:translateY(-1px);box-shadow:0 4px 16px rgba(249,115,22,.35)}
.btn-secondary{background:rgba(255,255,255,.07);color:#e2e8f0;border:1px solid rgba(255,255,255,.1);padding:10px 22px;border-radius:10px;font-weight:500;font-size:14px;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px;text-decoration:none}
.btn-secondary:hover{background:rgba(255,255,255,.12)}
.badge{display:inline-flex;align-items:center;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600}
.badge-success{background:rgba(34,197,94,.15);color:#22c55e}
.badge-warning{background:rgba(234,179,8,.15);color:#eab308}
.badge-danger{background:rgba(239,68,68,.15);color:#ef4444}
.badge-info{background:rgba(59,130,246,.15);color:#3b82f6}
.badge-orange{background:rgba(249,115,22,.15);color:#f97316}
.progress-bar{background:rgba(255,255,255,.07);border-radius:99px;overflow:hidden}
.progress-fill{height:100%;border-radius:99px;transition:width .8s}
.input{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;color:#e2e8f0;padding:10px 14px;font-size:14px;width:100%;transition:all .2s;outline:none;font-family:inherit}
.input:focus{border-color:#f97316;background:rgba(249,115,22,.05);box-shadow:0 0 0 3px rgba(249,115,22,.1)}
.input::placeholder{color:#4b5563}
.table-row{border-bottom:1px solid rgba(255,255,255,.04);transition:background .15s}
.table-row:hover{background:rgba(249,115,22,.04)}
.grad-text{background:linear-gradient(135deg,#f97316,#fb923c);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.glass{background:rgba(26,31,46,.8);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.07)}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.animate-fade-in{animation:fadeIn .4s ease-out}
@keyframes slideIn{from{transform:translateX(-16px);opacity:0}to{transform:translateX(0);opacity:1}}
.animate-slide{animation:slideIn .3s ease-out}
@media(max-width:768px){.sidebar{transform:translateX(-100%)}.sidebar.open{transform:translateX(0)}.main-content{margin-left:0}}
.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.error-box{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:12px 16px;border-radius:10px;font-size:13px;display:flex;align-items:center;gap:8px}
.success-box{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);color:#86efac;padding:12px 16px;border-radius:10px;font-size:13px;display:flex;align-items:center;gap:8px}
</style>
</head>
<body>${body}
<script>
function toggleSidebar(){document.getElementById('sidebar')?.classList.toggle('open')}
function closeModal(id){document.getElementById(id)?.classList.add('hidden')}
function openModal(id){document.getElementById(id)?.classList.remove('hidden')}
function showToast(msg,type='success'){
  const t=document.createElement('div');
  const c={success:'#22c55e',error:'#ef4444',warning:'#eab308',info:'#3b82f6'}[type]||'#22c55e';
  t.style.cssText='position:fixed;bottom:24px;right:24px;z-index:9999;background:'+c+';color:#fff;padding:12px 20px;border-radius:12px;font-size:14px;font-weight:500;display:flex;align-items:center;gap:10px;box-shadow:0 8px 32px rgba(0,0,0,.3);animation:fadeIn .3s ease-out';
  t.innerHTML='<i class="fas fa-check-circle"></i>'+msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(),3500);
}
// Counter animation
document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('[data-count]').forEach(el=>{
    const target=parseInt(el.dataset.count);let c=0;
    const step=target/50;
    const timer=setInterval(()=>{c+=step;if(c>=target){c=target;clearInterval(timer);}el.textContent=Math.floor(c).toLocaleString('fr-FR');},25);
  });
});
// API helper
async function apiPost(url, data){
  const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  return res.json();
}
function setLoading(btn,loading){
  if(loading){btn.dataset.orig=btn.innerHTML;btn.innerHTML='<span class="spinner"></span> Chargement...';btn.disabled=true;}
  else{btn.innerHTML=btn.dataset.orig||btn.innerHTML;btn.disabled=false;}
}
function showError(id,msg){
  const el=document.getElementById(id);
  if(el){el.innerHTML='<i class="fas fa-exclamation-circle"></i>'+msg;el.className='error-box mt-3';el.style.display='flex';}
}
function showSuccess(id,msg){
  const el=document.getElementById(id);
  if(el){el.innerHTML='<i class="fas fa-check-circle"></i>'+msg;el.className='success-box mt-3';el.style.display='flex';}
}
</script>
</body></html>`
}

// ─────────────────────────────────────────────────────────────────────────────
// SIDEBAR
// ─────────────────────────────────────────────────────────────────────────────
function sidebar(active: string) {
  const nav = [
    ['/dashboard','fa-grid-2','Tableau de bord',''],
    ['/chantiers','fa-hard-hat','Mes Chantiers',''],
    ['/budget','fa-chart-pie','Budget & Finances',''],
    ['/approvisionnements','fa-truck','Approvisionnements',''],
    ['/materiaux','fa-boxes-stacked','Matériaux & Stock',''],
    ['/journal','fa-book-open','Journal de Chantier',''],
    ['/alertes','fa-bell','Alertes & IA','3'],
    ['/rapports','fa-file-chart-column','Rapports',''],
  ]
  const bot = [
    ['/abonnements','fa-crown','Abonnements','PRO'],
    ['/profil','fa-user-circle','Mon Profil',''],
    ['/admin','fa-shield-halved','Administration',''],
  ]
  return `<aside class="sidebar" id="sidebar">
  <div class="p-5 border-b border-white/5">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-xl flex items-center justify-center" style="background:linear-gradient(135deg,#ea580c,#f97316)">
        <i class="fas fa-hard-hat text-white text-lg"></i>
      </div>
      <div>
        <div class="grad-text font-black text-lg leading-none">FasoChantier</div>
        <div class="text-xs text-slate-500 mt-0.5">v2.0 · Production</div>
      </div>
    </div>
  </div>
  <div class="mx-3 mt-3 mb-1 p-3 rounded-xl bg-white/[0.04] border border-white/[0.05] flex items-center gap-3" id="sidebar-user">
    <div class="w-9 h-9 rounded-full bg-gradient-to-br from-orange-500 to-orange-700 flex items-center justify-center text-white font-bold text-sm flex-shrink-0" id="sidebar-avatar">?</div>
    <div class="overflow-hidden">
      <div class="text-sm font-600 text-white truncate" id="sidebar-name">Chargement...</div>
      <div class="text-xs text-slate-500" id="sidebar-role">—</div>
    </div>
    <div class="ml-auto w-2 h-2 rounded-full bg-green-400 flex-shrink-0"></div>
  </div>
  <nav class="px-2 py-2">
    <div class="text-xs font-600 text-slate-600 uppercase tracking-wider px-3 mb-1 mt-2">Navigation</div>
    ${nav.map(([href,icon,label,badge]) => `
    <a href="${href}" class="nav-item ${active===href?'active':''}">
      <div class="nav-icon"><i class="fas ${icon}"></i></div>
      <span>${label}</span>
      ${badge ? `<span class="ml-auto badge badge-danger text-xs">${badge}</span>` : ''}
    </a>`).join('')}
    <div class="text-xs font-600 text-slate-600 uppercase tracking-wider px-3 mb-1 mt-4">Compte</div>
    ${bot.map(([href,icon,label,badge]) => `
    <a href="${href}" class="nav-item ${active===href?'active':''}">
      <div class="nav-icon"><i class="fas ${icon}"></i></div>
      <span>${label}</span>
      ${badge ? `<span class="ml-auto badge badge-orange text-xs">${badge}</span>` : ''}
    </a>`).join('')}
  </nav>
  <div class="mx-3 my-3 p-3 rounded-xl border border-white/5 bg-white/[0.02]">
    <div class="flex justify-between text-xs mb-1.5">
      <span class="text-slate-400">Chantiers actifs</span>
      <span class="text-orange-400 font-700">7/10</span>
    </div>
    <div class="progress-bar h-1.5 mb-1.5"><div class="progress-fill bg-orange-500" style="width:70%"></div></div>
    <a href="/abonnements" class="text-xs text-orange-400 hover:underline">Passer Entreprise →</a>
  </div>
  <div class="px-3 pb-4 border-t border-white/5 pt-2">
    <button onclick="doLogout()" class="nav-item w-full text-red-400 hover:bg-red-500/10 hover:text-red-400">
      <div class="nav-icon text-red-400"><i class="fas fa-right-from-bracket"></i></div>
      <span>Déconnexion</span>
    </button>
  </div>
</aside>
<script>
// Load user info
fetch('/api/auth/me').then(r=>r.json()).then(d=>{
  if(d.authenticated){
    const initials=(d.name||'?').split(' ').map(n=>n[0]).join('').slice(0,2).toUpperCase();
    document.getElementById('sidebar-avatar').textContent=initials;
    document.getElementById('sidebar-name').textContent=d.name||d.email||'Utilisateur';
    const roles={owner:'Propriétaire',controller:'Contrôleur',worker:'Tâcheron',admin:'Administrateur'};
    document.getElementById('sidebar-role').textContent=(roles[d.role]||d.role)+' · Pro';
  }
});
async function doLogout(){
  await fetch('/api/auth/logout',{method:'POST'});
  window.location.href='/login?msg=logged_out';
}
</script>`
}

// ─────────────────────────────────────────────────────────────────────────────
// TOPBAR
// ─────────────────────────────────────────────────────────────────────────────
function topbar(title: string, sub = '') {
  return `<header class="topbar px-6 py-4 flex items-center justify-between">
  <div class="flex items-center gap-4">
    <button onclick="toggleSidebar()" class="md:hidden w-9 h-9 flex items-center justify-center rounded-lg hover:bg-white/10 text-slate-400">
      <i class="fas fa-bars"></i>
    </button>
    <div>
      <h1 class="text-lg font-700 text-white leading-tight">${title}</h1>
      ${sub ? `<p class="text-xs text-slate-500">${sub}</p>` : ''}
    </div>
  </div>
  <div class="flex items-center gap-3">
    <div class="hidden md:flex items-center gap-2 bg-white/[0.05] border border-white/[0.08] rounded-10 px-3 py-2">
      <i class="fas fa-search text-slate-500 text-sm"></i>
      <input placeholder="Rechercher..." class="bg-transparent text-sm text-white outline-none placeholder:text-slate-600 w-44"/>
    </div>
    <div class="relative">
      <button class="w-9 h-9 flex items-center justify-center rounded-lg bg-white/[0.05] hover:bg-white/10 text-slate-300">
        <i class="fas fa-bell text-sm"></i>
      </button>
      <span class="absolute top-1.5 right-1.5 w-2 h-2 bg-orange-500 rounded-full"></span>
    </div>
    <a href="/chantiers" class="btn-primary hidden md:inline-flex text-sm py-2 px-4">
      <i class="fas fa-plus text-xs"></i> Nouveau Chantier
    </a>
  </div>
</header>`
}

// ─────────────────────────────────────────────────────────────────────────────
// PAGE LOGIN — avec vraie auth
// ─────────────────────────────────────────────────────────────────────────────
function loginPage(msg = '', err = '') {
  const msgBox = msg === 'logged_out' ? `<div class="success-box mb-4"><i class="fas fa-check-circle"></i>Vous avez été déconnecté avec succès.</div>` :
    msg === 'session_expired' ? `<div class="error-box mb-4"><i class="fas fa-exclamation-circle"></i>Votre session a expiré. Reconnectez-vous.</div>` : ''
  return shell('Connexion', `
<div class="min-h-screen flex" style="background:linear-gradient(135deg,#090b10 0%,#0f1117 60%,#13161f 100%)">
  <!-- Left decorative panel -->
  <div class="hidden lg:flex flex-col justify-between w-[460px] flex-shrink-0 p-10 relative overflow-hidden" style="background:linear-gradient(160deg,#13161f,#0f1117)">
    <div class="absolute inset-0 overflow-hidden pointer-events-none">
      <div class="absolute -top-24 -left-24 w-72 h-72 rounded-full opacity-15" style="background:radial-gradient(circle,#f97316,transparent)"></div>
      <div class="absolute -bottom-24 -right-24 w-96 h-96 rounded-full opacity-10" style="background:radial-gradient(circle,#ea580c,transparent)"></div>
    </div>
    <div class="relative z-10">
      <div class="flex items-center gap-3 mb-10">
        <div class="w-12 h-12 rounded-2xl flex items-center justify-center shadow-lg" style="background:linear-gradient(135deg,#ea580c,#f97316)">
          <i class="fas fa-hard-hat text-white text-xl"></i>
        </div>
        <div>
          <div class="font-black text-xl text-white">FasoChantier</div>
          <div class="text-xs text-slate-500">Contrôle Intelligent de Chantier</div>
        </div>
      </div>
      <h2 class="text-3xl font-800 text-white leading-tight mb-3">Gérez votre chantier<br/>depuis n'importe où</h2>
      <p class="text-slate-400 text-sm leading-relaxed mb-8">Suivi des matériaux, contrôle des dépenses et alertes instantanées. Même sans connexion internet.</p>
      <div class="space-y-4">
        ${[['fa-shield-check','#22c55e','Protection Anti-Vol','Validation photo de chaque livraison'],
           ['fa-chart-line-up','#3b82f6','Suivi Budgétaire','Graphiques et alertes en temps réel'],
           ['fa-robot','#a855f7','IA de Détection','Anomalies et fraudes automatiquement'],
           ['fa-wifi-slash','#f97316','Offline-First','Synchronisation automatique']
          ].map(([icon,color,t,d]) => `
        <div class="flex items-start gap-3">
          <div class="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0" style="background:${color}20">
            <i class="fas ${icon} text-sm" style="color:${color}"></i>
          </div>
          <div><div class="font-600 text-sm text-white">${t}</div><div class="text-xs text-slate-500">${d}</div></div>
        </div>`).join('')}
      </div>
    </div>
    <div class="relative z-10 glass rounded-2xl p-4">
      <div class="flex gap-1 mb-2">${'<i class="fas fa-star text-yellow-400 text-xs"></i>'.repeat(5)}</div>
      <p class="text-sm text-slate-300 italic">"FasoChantier m'a permis d'économiser 2 millions de FCFA en détectant des livraisons fantômes sur mon chantier."</p>
      <div class="flex items-center gap-2 mt-3">
        <div class="w-8 h-8 rounded-full bg-gradient-to-br from-orange-500 to-red-600 flex items-center justify-center text-white text-xs font-700">MB</div>
        <div><div class="text-xs font-600 text-white">Moussa Belemkieta</div><div class="text-xs text-slate-500">Entrepreneur — Ouagadougou</div></div>
      </div>
    </div>
  </div>

  <!-- Right form panel -->
  <div class="flex-1 flex items-center justify-center p-6">
    <div class="w-full max-w-[420px] animate-fade-in">
      <div class="lg:hidden flex items-center gap-3 mb-8 justify-center">
        <div class="w-10 h-10 rounded-xl flex items-center justify-center" style="background:linear-gradient(135deg,#ea580c,#f97316)">
          <i class="fas fa-hard-hat text-white"></i>
        </div>
        <div class="grad-text font-black text-xl">FasoChantier</div>
      </div>
      <div class="card p-8">
        <div class="mb-6">
          <h2 class="text-2xl font-800 text-white">Bon retour 👋</h2>
          <p class="text-slate-500 text-sm mt-1">Connectez-vous pour accéder à votre espace</p>
        </div>
        ${msgBox}
        <div id="login-msg" class="hidden"></div>

        <form id="login-form" class="space-y-4" onsubmit="handleLogin(event)">
          <div>
            <label class="text-sm font-500 text-slate-400 mb-1.5 block">Adresse email</label>
            <input type="email" id="login-email" placeholder="votre@email.com" class="input" required autocomplete="email"/>
          </div>
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-sm font-500 text-slate-400">Mot de passe</label>
              <a href="#" class="text-xs text-orange-400 hover:underline">Mot de passe oublié ?</a>
            </div>
            <div class="relative">
              <input type="password" id="login-pwd" placeholder="••••••••" class="input pr-10" required autocomplete="current-password"/>
              <button type="button" onclick="togglePwd('login-pwd','eye1')" class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                <i class="fas fa-eye text-sm" id="eye1"></i>
              </button>
            </div>
          </div>
          <label class="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked class="w-4 h-4 accent-orange-500 rounded"/>
            <span class="text-sm text-slate-400">Rester connecté</span>
          </label>
          <button type="submit" id="login-btn" class="btn-primary w-full justify-center py-3 text-base mt-1">
            <i class="fas fa-right-to-bracket"></i> Se connecter
          </button>
        </form>

        <div class="flex items-center gap-3 my-5">
          <div class="flex-1 h-px bg-white/10"></div>
          <span class="text-xs text-slate-600">ou</span>
          <div class="flex-1 h-px bg-white/10"></div>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <button onclick="showToast('Google Auth bientôt disponible','info')" class="btn-secondary justify-center py-2.5 text-sm"><i class="fab fa-google text-red-400"></i> Google</button>
          <button onclick="showToast('WhatsApp Auth bientôt disponible','info')" class="btn-secondary justify-center py-2.5 text-sm"><i class="fab fa-whatsapp text-green-400"></i> WhatsApp</button>
        </div>
        <p class="text-center text-sm text-slate-500 mt-5">
          Pas encore inscrit ? <a href="/register" class="text-orange-400 font-600 hover:underline">Créer un compte</a>
        </p>
      </div>
      <div class="flex items-center justify-center gap-6 mt-5">
        <div class="flex items-center gap-1.5 text-xs text-slate-600"><i class="fas fa-lock text-green-400"></i> SSL Sécurisé</div>
        <div class="flex items-center gap-1.5 text-xs text-slate-600"><i class="fas fa-shield text-blue-400"></i> RGPD Conforme</div>
        <div class="flex items-center gap-1.5 text-xs text-slate-600"><i class="fas fa-wifi-slash text-orange-400"></i> Offline Ready</div>
      </div>
    </div>
  </div>
</div>
<script>
function togglePwd(id,eyeId){
  const f=document.getElementById(id);const e=document.getElementById(eyeId);
  if(f.type==='password'){f.type='text';e.classList.replace('fa-eye','fa-eye-slash');}
  else{f.type='password';e.classList.replace('fa-eye-slash','fa-eye');}
}
async function handleLogin(e){
  e.preventDefault();
  const btn=document.getElementById('login-btn');
  const email=document.getElementById('login-email').value.trim();
  const password=document.getElementById('login-pwd').value;
  setLoading(btn,true);
  document.getElementById('login-msg').style.display='none';
  try{
    const data=await apiPost('/api/auth/login',{email,password});
    if(data.success){
      showSuccess('login-msg','Connexion réussie ! Redirection...');
      setTimeout(()=>window.location.href=data.redirect||'/dashboard',800);
    } else {
      showError('login-msg',data.error||'Identifiants incorrects');
      setLoading(btn,false);
    }
  } catch(err){
    showError('login-msg','Erreur réseau. Vérifiez votre connexion.');
    setLoading(btn,false);
  }
}
</script>`)
}

// ─────────────────────────────────────────────────────────────────────────────
// PAGE REGISTER — avec vraie auth
// ─────────────────────────────────────────────────────────────────────────────
function registerPage() {
  return shell('Inscription', `
<div class="min-h-screen flex items-center justify-center p-6" style="background:linear-gradient(135deg,#090b10,#0f1117)">
  <div class="w-full max-w-[540px] animate-fade-in">
    <div class="text-center mb-8">
      <div class="inline-flex items-center gap-3 mb-4">
        <div class="w-12 h-12 rounded-2xl flex items-center justify-center" style="background:linear-gradient(135deg,#ea580c,#f97316)">
          <i class="fas fa-hard-hat text-white text-xl"></i>
        </div>
      </div>
      <h1 class="text-3xl font-800 text-white">Créer votre compte</h1>
      <p class="text-slate-500 text-sm mt-2">Commencez à contrôler votre chantier en 2 minutes</p>
    </div>
    <div class="card p-8">
      <!-- Plan selector -->
      <div class="mb-6">
        <label class="text-sm font-500 text-slate-400 mb-3 block">Choisissez votre formule</label>
        <div class="grid grid-cols-3 gap-2">
          ${[['basic','Basic','50k FCFA','fa-seedling','#94a3b8'],
             ['pro','Pro','100k FCFA','fa-rocket','#f97316'],
             ['enterprise','Entreprise','Sur devis','fa-building','#a855f7']
            ].map(([val,label,price,icon,color],i) => `
          <label class="cursor-pointer">
            <input type="radio" name="plan_sel" value="${val}" class="hidden peer" ${i===1?'checked':''}>
            <div class="peer-checked:border-orange-500 peer-checked:bg-orange-500/10 border border-white/10 rounded-xl p-3 text-center transition-all hover:border-white/20">
              <i class="fas ${icon} mb-1 block text-lg" style="color:${color}"></i>
              <div class="text-xs font-700 text-white">${label}</div>
              <div class="text-xs text-slate-500">${price}</div>
            </div>
          </label>`).join('')}
        </div>
      </div>

      <div id="register-msg" class="hidden mb-3"></div>

      <form id="register-form" class="space-y-4" onsubmit="handleRegister(event)">
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="text-xs font-500 text-slate-400 mb-1 block">Prénom *</label>
            <input type="text" id="reg-firstname" placeholder="Kofi" class="input" required/>
          </div>
          <div>
            <label class="text-xs font-500 text-slate-400 mb-1 block">Nom *</label>
            <input type="text" id="reg-lastname" placeholder="Sawadogo" class="input" required/>
          </div>
        </div>
        <div>
          <label class="text-xs font-500 text-slate-400 mb-1 block">Email *</label>
          <input type="email" id="reg-email" placeholder="kofi@example.com" class="input" required autocomplete="email"/>
        </div>
        <div>
          <label class="text-xs font-500 text-slate-400 mb-1 block">Téléphone / WhatsApp *</label>
          <div class="flex gap-2">
            <select id="reg-prefix" class="input w-28 flex-shrink-0">
              <option value="+226">🇧🇫 +226</option>
              <option value="+225">🇨🇮 +225</option>
              <option value="+221">🇸🇳 +221</option>
              <option value="+223">🇲🇱 +223</option>
              <option value="+33">🇫🇷 +33</option>
              <option value="+1">🇺🇸 +1</option>
            </select>
            <input type="tel" id="reg-phone" placeholder="70 00 00 00" class="input flex-1" required/>
          </div>
        </div>
        <div>
          <label class="text-xs font-500 text-slate-400 mb-1 block">Rôle</label>
          <select id="reg-role" class="input">
            <option value="owner">Propriétaire</option>
            <option value="controller">Contrôleur de chantier</option>
            <option value="worker">Tâcheron / Maçon</option>
          </select>
        </div>
        <div>
          <label class="text-xs font-500 text-slate-400 mb-1 block">Pays de résidence</label>
          <select id="reg-country" class="input">
            <option value="BF">🇧🇫 Burkina Faso</option>
            <option value="CI">🇨🇮 Côte d'Ivoire</option>
            <option value="SN">🇸🇳 Sénégal</option>
            <option value="ML">🇲🇱 Mali</option>
            <option value="FR">🇫🇷 France (Diaspora)</option>
            <option value="US">🇺🇸 USA (Diaspora)</option>
          </select>
        </div>
        <div>
          <label class="text-xs font-500 text-slate-400 mb-1 block">Mot de passe * (min. 8 caractères)</label>
          <div class="relative">
            <input type="password" id="reg-pwd" placeholder="Minimum 8 caractères" class="input pr-10" required autocomplete="new-password" minlength="8"/>
            <button type="button" onclick="togglePwd2()" class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
              <i class="fas fa-eye text-sm" id="eye2"></i>
            </button>
          </div>
        </div>
        <label class="flex items-start gap-2 cursor-pointer">
          <input type="checkbox" id="reg-terms" class="w-4 h-4 accent-orange-500 rounded mt-0.5" required/>
          <span class="text-xs text-slate-400">J'accepte les <a href="#" class="text-orange-400 hover:underline">Conditions d'utilisation</a> et la <a href="#" class="text-orange-400 hover:underline">Politique de confidentialité</a></span>
        </label>
        <button type="submit" id="reg-btn" class="btn-primary w-full justify-center py-3 text-base">
          <i class="fas fa-user-plus"></i> Créer mon compte
        </button>
      </form>
      <p class="text-center text-sm text-slate-500 mt-5">
        Déjà inscrit ? <a href="/login" class="text-orange-400 font-600 hover:underline">Se connecter</a>
      </p>
    </div>
  </div>
</div>
<script>
function togglePwd2(){
  const f=document.getElementById('reg-pwd');const e=document.getElementById('eye2');
  if(f.type==='password'){f.type='text';e.classList.replace('fa-eye','fa-eye-slash');}
  else{f.type='password';e.classList.replace('fa-eye-slash','fa-eye');}
}
async function handleRegister(e){
  e.preventDefault();
  const btn=document.getElementById('reg-btn');
  const firstname=document.getElementById('reg-firstname').value.trim();
  const lastname=document.getElementById('reg-lastname').value.trim();
  const email=document.getElementById('reg-email').value.trim();
  const prefix=document.getElementById('reg-prefix').value;
  const phone=document.getElementById('reg-phone').value.trim();
  const role=document.getElementById('reg-role').value;
  const country=document.getElementById('reg-country').value;
  const password=document.getElementById('reg-pwd').value;
  const full_name=firstname+' '+lastname;
  const fullphone=prefix+phone;
  if(password.length<8){showError('register-msg','Le mot de passe doit avoir au moins 8 caractères');return;}
  setLoading(btn,true);
  document.getElementById('register-msg').style.display='none';
  try{
    const data=await apiPost('/api/auth/register',{
      email,password,full_name,phone:fullphone,
      role,country,whatsapp_number:fullphone,
      is_diaspora:country==='FR'||country==='US'
    });
    if(data.success){
      showSuccess('register-msg','Compte créé avec succès ! Redirection...');
      setTimeout(()=>window.location.href=data.redirect||'/dashboard',1000);
    } else {
      showError('register-msg',data.error||'Erreur lors de la création du compte');
      setLoading(btn,false);
    }
  } catch(err){
    showError('register-msg','Erreur réseau. Vérifiez votre connexion.');
    setLoading(btn,false);
  }
}
</script>`)
}

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────
function dashboardPage(userName = 'Utilisateur', userRole = 'owner') {
  const roleLabel: Record<string, string> = { owner: 'Propriétaire', controller: 'Contrôleur', worker: 'Tâcheron', admin: 'Administrateur' }
  return shell('Tableau de bord', `
<div class="flex">
  ${sidebar('/dashboard')}
  <div class="main-content flex-1">
    ${topbar('Tableau de bord', `Bonjour ${userName} 👋 — ${roleLabel[userRole] || userRole}`)}
    <main class="p-6 space-y-6 animate-fade-in">
      <!-- KPIs -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
        ${[
          {label:'Budget Total',val:'145 000 000',unit:'FCFA',icon:'fa-wallet',color:'#f97316',border:'border-l-orange-500',cnt:'145000000',delta:'Tous chantiers'},
          {label:'Dépenses',val:'89 200 000',unit:'FCFA',icon:'fa-money-bill-trend-up',color:'#ef4444',border:'border-l-red-500',cnt:'89200000',delta:'61.5% du budget'},
          {label:'Chantiers Actifs',val:'7',unit:'/ 12 total',icon:'fa-hard-hat',color:'#22c55e',border:'border-l-green-500',cnt:'7',delta:'+1 cette semaine'},
          {label:'Alertes',val:'3',unit:'à traiter',icon:'fa-triangle-exclamation',color:'#eab308',border:'border-l-yellow-500',cnt:'3',delta:'1 critique'}
        ].map(k => `
        <div class="card border-l-2 ${k.border} p-5">
          <div class="flex items-start justify-between mb-3">
            <div>
              <div class="text-xs font-500 text-slate-500 mb-1">${k.label}</div>
              <div class="text-2xl font-800 text-white leading-none" data-count="${k.cnt}">${k.val}</div>
              <div class="text-xs text-slate-500 mt-0.5">${k.unit}</div>
            </div>
            <div class="w-10 h-10 rounded-xl flex items-center justify-center" style="background:${k.color}20">
              <i class="fas ${k.icon}" style="color:${k.color}"></i>
            </div>
          </div>
          <div class="text-xs text-slate-500">${k.delta}</div>
        </div>`).join('')}
      </div>

      <div class="grid lg:grid-cols-3 gap-6">
        <!-- Chart dépenses -->
        <div class="card p-6 lg:col-span-2">
          <div class="flex items-center justify-between mb-5">
            <div><h3 class="font-700 text-white">Évolution des Dépenses</h3><p class="text-xs text-slate-500">6 derniers mois — en millions FCFA</p></div>
            <span class="badge badge-orange text-xs">Temps réel</span>
          </div>
          <div class="flex items-end gap-3 h-36 mb-3">
            ${[['Jan',65],['Fév',48],['Mar',80],['Avr',55],['Mai',92],['Jui',70]].map(([m,p]) => `
            <div class="flex-1 flex flex-col items-center gap-2">
              <div class="text-xs text-slate-500 font-600">${Math.round(Number(p)*1.45)}M</div>
              <div class="w-full rounded-t-md" style="height:${p}%;background:linear-gradient(180deg,#f97316,#ea580c88)"></div>
              <div class="text-xs text-slate-600">${m}</div>
            </div>`).join('')}
          </div>
          <div class="flex items-center gap-4 text-xs text-slate-500 border-t border-white/5 pt-3">
            <div class="flex items-center gap-1.5"><div class="w-2.5 h-2.5 rounded-full bg-orange-500"></div>Dépenses réelles</div>
          </div>
        </div>
        <!-- Risk score -->
        <div class="space-y-4">
          <div class="card p-5">
            <div class="flex items-center justify-between mb-4">
              <h3 class="font-700 text-white text-sm">Score Risque IA</h3>
              <span class="badge badge-warning">MODÉRÉ</span>
            </div>
            <div class="relative flex items-center justify-center mb-4">
              <svg viewBox="0 0 120 120" class="w-28 h-28">
                <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="10"/>
                <circle cx="60" cy="60" r="50" fill="none" stroke="#eab308" stroke-width="10"
                  stroke-dasharray="75.4 239" stroke-linecap="round" transform="rotate(-90 60 60)"/>
              </svg>
              <div class="absolute text-center">
                <div class="text-3xl font-900 text-yellow-400">24</div>
                <div class="text-xs text-slate-500">/100</div>
              </div>
            </div>
            <div class="space-y-2 text-xs">
              ${[['Anomalies prix','2','#ef4444'],['Retards','1','#eab308'],['Livraisons ok','45','#22c55e']].map(([l,n,c]) => `
              <div class="flex items-center justify-between">
                <span class="text-slate-400">${l}</span>
                <span class="font-700" style="color:${c}">${n}</span>
              </div>`).join('')}
            </div>
          </div>
          <div class="card p-5">
            <h3 class="font-700 text-white text-sm mb-3">Répartition Budget</h3>
            <div class="space-y-2.5">
              ${[['Matériaux',55,'#f97316'],['Main d\'œuvre',30,'#3b82f6'],['Transport',10,'#a855f7'],['Divers',5,'#22c55e']].map(([c,p,col]) => `
              <div>
                <div class="flex justify-between text-xs mb-1"><span class="text-slate-400">${c}</span><span style="color:${col}" class="font-600">${p}%</span></div>
                <div class="progress-bar h-1.5"><div class="progress-fill" style="width:${p}%;background:${col}"></div></div>
              </div>`).join('')}
            </div>
          </div>
        </div>
      </div>

      <!-- Chantiers table -->
      <div class="card p-6">
        <div class="flex items-center justify-between mb-5">
          <h3 class="font-700 text-white">Chantiers en cours</h3>
          <a href="/chantiers" class="btn-secondary text-sm py-2 px-4">Voir tous <i class="fas fa-arrow-right text-xs ml-1"></i></a>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead><tr class="border-b border-white/5">
              <th class="text-left py-2 px-3 text-xs font-600 text-slate-500">CHANTIER</th>
              <th class="text-left py-2 px-3 text-xs font-600 text-slate-500">AVANCEMENT</th>
              <th class="text-left py-2 px-3 text-xs font-600 text-slate-500">BUDGET</th>
              <th class="text-left py-2 px-3 text-xs font-600 text-slate-500">RISQUE</th>
              <th class="text-left py-2 px-3 text-xs font-600 text-slate-500">STATUT</th>
              <th class="py-2 px-3"></th>
            </tr></thead>
            <tbody>
              ${[
                {name:'Villa Familiale — Zone 1',loc:'Ouagadougou',prog:68,budget:'45M',spent:'30.6M',risk:15,rc:'text-green-400'},
                {name:'Maison R+1 — Pissy',loc:'Ouagadougou',prog:35,budget:'28M',spent:'9.8M',risk:42,rc:'text-yellow-400'},
                {name:'Commerce Gounghin',loc:'Ouagadougou',prog:82,budget:'18M',spent:'14.7M',risk:8,rc:'text-green-400'},
                {name:'Villa Bobo-Dioulasso',loc:'Bobo-Dioulasso',prog:20,budget:'54M',spent:'10.8M',risk:71,rc:'text-red-400'},
              ].map(c => `
              <tr class="table-row">
                <td class="py-3 px-3">
                  <div class="font-600 text-sm text-white">${c.name}</div>
                  <div class="text-xs text-slate-500"><i class="fas fa-location-dot text-orange-500 mr-1"></i>${c.loc}</div>
                </td>
                <td class="py-3 px-3">
                  <div class="flex items-center gap-2">
                    <div class="progress-bar h-1.5 w-20"><div class="progress-fill bg-orange-500" style="width:${c.prog}%"></div></div>
                    <span class="text-xs font-600 text-white">${c.prog}%</span>
                  </div>
                </td>
                <td class="py-3 px-3">
                  <div class="text-xs text-white font-600">${c.spent} FCFA</div>
                  <div class="text-xs text-slate-500">/ ${c.budget}</div>
                </td>
                <td class="py-3 px-3 text-sm font-700 ${c.rc}">${c.risk}/100</td>
                <td class="py-3 px-3"><span class="badge badge-success">Actif</span></td>
                <td class="py-3 px-3"><a href="/chantier/1" class="text-orange-400 hover:text-orange-300"><i class="fas fa-arrow-right"></i></a></td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Alertes + Activité -->
      <div class="grid lg:grid-cols-2 gap-6">
        <div class="card p-6">
          <div class="flex items-center justify-between mb-4">
            <h3 class="font-700 text-white">Alertes Récentes</h3>
            <a href="/alertes" class="text-xs text-orange-400 hover:underline">Voir toutes</a>
          </div>
          <div class="space-y-3">
            ${[
              {icon:'fa-triangle-exclamation',color:'#ef4444',title:'Prix anormal détecté',desc:'Ciment à 18 000 FCFA/sac — marché: 12 000',time:'12 min'},
              {icon:'fa-boxes-stacked',color:'#eab308',title:'Stock de fer faible',desc:'Moins de 10% restant — Villa Zone 1',time:'1h'},
              {icon:'fa-truck',color:'#3b82f6',title:'Livraison en attente',desc:'50 sacs ciment à valider',time:'2h'},
            ].map(a => `
            <div class="flex items-start gap-3 p-3 rounded-xl border border-white/5 hover:border-white/10 cursor-pointer transition-all">
              <div class="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0" style="background:${a.color}18">
                <i class="fas ${a.icon} text-sm" style="color:${a.color}"></i>
              </div>
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between">
                  <div class="font-600 text-sm text-white truncate">${a.title}</div>
                  <div class="text-xs text-slate-600 flex-shrink-0 ml-2">${a.time}</div>
                </div>
                <div class="text-xs text-slate-500">${a.desc}</div>
              </div>
            </div>`).join('')}
          </div>
        </div>
        <div class="card p-6">
          <div class="flex items-center justify-between mb-4">
            <h3 class="font-700 text-white">Activité Récente</h3>
            <a href="/journal" class="text-xs text-orange-400 hover:underline">Journal</a>
          </div>
          <div class="space-y-4">
            ${[
              {user:'Ibrahim K.',action:'a validé une livraison',detail:'80 briques — Villa Zone 1',time:'14:32',color:'#22c55e'},
              {user:'Awa Traoré',action:'a soumis un rapport',detail:'Fondations 85% terminées',time:'13:15',color:'#3b82f6'},
              {user:'IA FasoChantier',action:'a détecté une anomalie',detail:'Prix du sable +40%',time:'11:02',color:'#a855f7'},
              {user:'${userName}',action:'s\'est connecté',detail:'Depuis votre appareil',time:'Maintenant',color:'#f97316'},
            ].map(a => `
            <div class="flex items-start gap-3">
              <div class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-xs font-700 text-white flex-shrink-0">
                ${a.user.split(' ').map((n: string)=>n[0]).join('').slice(0,2).toUpperCase()}
              </div>
              <div class="flex-1">
                <div class="text-xs text-white"><span class="font-600">${a.user}</span> <span class="text-slate-400">${a.action}</span></div>
                <div class="text-xs text-slate-500">${a.detail}</div>
              </div>
              <div class="text-xs text-slate-600 flex-shrink-0">${a.time}</div>
            </div>`).join('')}
          </div>
        </div>
      </div>
    </main>
  </div>
</div>`)
}

// ─────────────────────────────────────────────────────────────────────────────
// PAGES SIMPLIFIÉES (toutes les autres pages)
// ─────────────────────────────────────────────────────────────────────────────
function chantiersPage() {
  return shell('Mes Chantiers', `<div class="flex">${sidebar('/chantiers')}<div class="main-content flex-1">${topbar('Mes Chantiers','12 chantiers au total — 7 actifs')}<main class="p-6 animate-fade-in">
  <div class="flex flex-wrap items-center gap-3 mb-6">
    <div class="flex gap-2">${['Tous','Actifs','En pause','Terminés'].map((f,i)=>`<button class="${i===0?'btn-primary':'btn-secondary'} text-sm py-2 px-4">${f}</button>`).join('')}</div>
    <button onclick="openModal('modal-nc')" class="ml-auto btn-primary"><i class="fas fa-plus"></i> Nouveau chantier</button>
  </div>
  <div class="grid md:grid-cols-2 xl:grid-cols-3 gap-5">
    ${[
      {id:1,name:'Villa Familiale — Zone 1',type:'Villa',loc:'Ouagadougou',prog:68,budget:'45 000 000',spent:'30 600 000',surface:220,risk:15,status:'active'},
      {id:2,name:'Maison R+1 — Pissy',type:'Maison',loc:'Ouagadougou',prog:35,budget:'28 000 000',spent:'9 800 000',surface:160,risk:42,status:'active'},
      {id:3,name:'Commerce Gounghin',type:'Commercial',loc:'Ouagadougou',prog:82,budget:'18 000 000',spent:'14 700 000',surface:80,risk:8,status:'active'},
      {id:4,name:'Villa Bobo-Dioulasso',type:'Villa',loc:'Bobo-Dioulasso',prog:20,budget:'54 000 000',spent:'10 800 000',surface:300,risk:71,status:'active'},
      {id:5,name:'Appartement Karpala',type:'Appartement',loc:'Ouagadougou',prog:100,budget:'22 000 000',spent:'21 500 000',surface:110,risk:5,status:'completed'},
      {id:6,name:'Villa Diaspora — Bassin',type:'Villa',loc:'Ouagadougou',prog:5,budget:'75 000 000',spent:'3 750 000',surface:400,risk:20,status:'planning'},
    ].map(c => `
    <div class="card p-5 cursor-pointer group" onclick="location.href='/chantier/${c.id}'">
      <div class="flex items-start justify-between mb-3">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center" style="background:linear-gradient(135deg,rgba(249,115,22,.2),rgba(234,88,12,.15))">
            <i class="fas fa-hard-hat text-orange-400"></i>
          </div>
          <div>
            <div class="font-700 text-sm text-white group-hover:text-orange-400 transition-colors">${c.name}</div>
            <div class="text-xs text-slate-500">${c.type} · ${c.surface} m²</div>
          </div>
        </div>
        <span class="badge ${c.status==='active'?'badge-success':c.status==='completed'?'badge-info':'badge-orange'}">${c.status==='active'?'Actif':c.status==='completed'?'Terminé':'Planning'}</span>
      </div>
      <div class="flex items-center gap-1.5 text-xs text-slate-500 mb-3"><i class="fas fa-location-dot text-orange-500"></i>${c.loc}</div>
      <div class="mb-4">
        <div class="flex justify-between text-xs mb-1.5"><span class="text-slate-400">Avancement</span><span class="font-700 text-white">${c.prog}%</span></div>
        <div class="progress-bar h-2"><div class="progress-fill ${c.prog>80?'bg-green-500':c.prog>40?'bg-orange-500':'bg-blue-500'}" style="width:${c.prog}%"></div></div>
      </div>
      <div class="flex items-center justify-between bg-white/[0.03] rounded-lg p-3 mb-3">
        <div class="text-center"><div class="text-xs text-slate-500">Total</div><div class="text-sm font-700 text-white">${c.budget}</div></div>
        <div class="w-px h-8 bg-white/10"></div>
        <div class="text-center"><div class="text-xs text-slate-500">Dépensé</div><div class="text-sm font-700 text-orange-400">${c.spent}</div></div>
        <div class="w-px h-8 bg-white/10"></div>
        <div class="text-center"><div class="text-xs text-slate-500">Risque</div><div class="text-sm font-700 ${c.risk<30?'text-green-400':c.risk<60?'text-yellow-400':'text-red-400'}">${c.risk}/100</div></div>
      </div>
      <a href="/chantier/${c.id}" class="text-xs text-orange-400 hover:underline flex items-center gap-1">Voir détails <i class="fas fa-arrow-right text-xs"></i></a>
    </div>`).join('')}
  </div>
</main></div></div>
<div id="modal-nc" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4" style="background:rgba(0,0,0,.7);backdrop-filter:blur(8px)">
  <div class="card w-full max-w-[560px] max-h-[90vh] overflow-y-auto animate-fade-in">
    <div class="flex items-center justify-between p-6 border-b border-white/5">
      <div><h2 class="font-700 text-white text-lg">Nouveau Chantier</h2><p class="text-xs text-slate-500">Remplissez les informations</p></div>
      <button onclick="closeModal('modal-nc')" class="text-slate-400 hover:text-white"><i class="fas fa-times"></i></button>
    </div>
    <div class="p-6 space-y-4">
      <div><label class="text-xs text-slate-400 mb-1 block">Nom du chantier *</label><input type="text" placeholder="Villa Familiale Zone 1" class="input"/></div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="text-xs text-slate-400 mb-1 block">Type</label><select class="input"><option>Villa</option><option>Maison</option><option>Appartement</option><option>Commercial</option></select></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Pièces</label><input type="number" placeholder="5" class="input"/></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Surface (m²)</label><input type="number" placeholder="220" class="input"/></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Budget (FCFA)</label><input type="number" placeholder="45000000" class="input"/></div>
      </div>
      <div><label class="text-xs text-slate-400 mb-1 block">Localisation</label><input type="text" placeholder="Ouagadougou, Secteur 15" class="input"/></div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="text-xs text-slate-400 mb-1 block">Début prévu</label><input type="date" class="input"/></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Fin prévue</label><input type="date" class="input"/></div>
      </div>
      <div class="flex gap-3 pt-2">
        <button onclick="closeModal('modal-nc')" class="btn-secondary flex-1 justify-center">Annuler</button>
        <button onclick="showToast('Chantier créé avec succès !');closeModal('modal-nc')" class="btn-primary flex-1 justify-center"><i class="fas fa-plus"></i> Créer</button>
      </div>
    </div>
  </div>
</div>`)
}

function chantierDetailPage(id: string) {
  return shell('Détail Chantier', `<div class="flex">${sidebar('/chantiers')}<div class="main-content flex-1">${topbar('Villa Familiale — Zone 1','Chantier #'+id+' · Ouagadougou · Actif')}<main class="p-6 animate-fade-in space-y-6">
  <div class="card p-6" style="border-top:3px solid #f97316">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <div class="flex items-center gap-2 mb-1"><span class="badge badge-success">Actif</span><span class="badge badge-orange">Villa · 5 pièces · 220 m²</span></div>
        <h2 class="text-2xl font-800 text-white mb-1">Villa Familiale — Zone 1</h2>
        <div class="text-sm text-slate-400"><i class="fas fa-location-dot text-orange-500 mr-1"></i>Ouagadougou, Secteur 15 · Créé le 15 Jan 2025</div>
      </div>
      <div class="flex gap-2 flex-wrap">
        <button onclick="showToast('Rapport PDF généré !','success')" class="btn-secondary text-sm py-2 px-4"><i class="fas fa-file-pdf"></i> PDF</button>
        <button onclick="showToast('Photo ajoutée','success')" class="btn-primary text-sm py-2 px-4"><i class="fas fa-camera"></i> Photo</button>
      </div>
    </div>
    <div class="mt-4">
      <div class="flex justify-between text-sm mb-2"><span class="text-slate-400">Avancement global</span><span class="text-white font-700">68%</span></div>
      <div class="progress-bar h-3"><div class="progress-fill bg-gradient-to-r from-orange-600 to-orange-400" style="width:68%"></div></div>
    </div>
  </div>
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    ${[['Budget Total','45 000 000 FCFA','fa-wallet','#f97316'],['Dépensé','30 600 000 FCFA','fa-money-bill-wave','#ef4444'],['Restant','14 400 000 FCFA','fa-piggy-bank','#22c55e'],['Coût/m²','138 636 FCFA','fa-calculator','#3b82f6']].map(([l,v,i,c]) => `
    <div class="card p-4">
      <div class="flex items-center gap-2 mb-2"><div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background:${c}20"><i class="fas ${i} text-xs" style="color:${c}"></i></div><span class="text-xs text-slate-500">${l}</span></div>
      <div class="text-lg font-800 text-white">${v}</div>
    </div>`).join('')}
  </div>
  <div class="grid lg:grid-cols-2 gap-6">
    <div class="card p-5">
      <h3 class="font-700 text-white mb-4">Phases du Chantier</h3>
      <div class="space-y-3">
        ${[['Fondations',100,'#22c55e','done'],['Gros œuvre',80,'#f97316','active'],['Toiture/Dalle',45,'#3b82f6','active'],['Crépissage',0,'#6b7280','pending'],['Second œuvre',0,'#6b7280','pending'],['Finitions',0,'#6b7280','pending']].map(([p,pct,c,s]) => `
        <div class="flex items-center gap-3">
          <div class="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0" style="background:${c}20">
            <i class="fas ${s==='done'?'fa-check':s==='active'?'fa-circle-half-stroke':'fa-clock'} text-xs" style="color:${c}"></i>
          </div>
          <div class="flex-1">
            <div class="flex justify-between text-xs mb-1"><span class="text-slate-300 font-500">${p}</span><span class="font-700" style="color:${c}">${pct}%</span></div>
            <div class="progress-bar h-1"><div class="progress-fill" style="width:${pct}%;background:${c}"></div></div>
          </div>
        </div>`).join('')}
      </div>
    </div>
    <div class="card p-5">
      <div class="flex items-center justify-between mb-4"><h3 class="font-700 text-white">Stock Matériaux</h3><a href="/materiaux" class="text-xs text-orange-400">Gérer</a></div>
      <div class="space-y-3">
        ${[['Ciment','200 sacs','165 sacs','#f97316',false],['Sable','15 m³','10 m³','#eab308',false],['Gravier','12 m³','9 m³','#3b82f6',false],['Fer HA12','2.5t','2.3t','#ef4444',true],['Briques','3000','1800','#a855f7',false]].map(([m,r,u,c,danger]) => `
        <div class="flex items-center gap-3 p-2 rounded-lg ${danger?'bg-red-500/5 border border-red-500/20':'bg-white/[0.02]'}">
          <i class="fas fa-cube text-xs flex-shrink-0" style="color:${c}"></i>
          <div class="flex-1">
            <div class="flex justify-between text-xs mb-0.5"><span class="text-slate-300 font-500">${m}</span><span class="text-slate-400">${u}/${r}</span></div>
            <div class="progress-bar h-1"><div class="progress-fill" style="width:${danger?'92':'65'}%;background:${c}"></div></div>
          </div>
          ${danger?'<i class="fas fa-exclamation-triangle text-red-400 text-xs flex-shrink-0"></i>':''}
        </div>`).join('')}
      </div>
    </div>
  </div>
</main></div></div>`)
}

function budgetPage() {
  return shell('Budget & Finances', `<div class="flex">${sidebar('/budget')}<div class="main-content flex-1">${topbar('Budget & Finances','Suivi intelligent de vos dépenses')}<main class="p-6 animate-fade-in space-y-6">
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    ${[['Budget Total','145 000 000','#f97316','fa-wallet'],['Dépensé','89 200 000','#ef4444','fa-arrow-up-from-bracket'],['Restant','55 800 000','#22c55e','fa-shield-check'],['Économisé','4 300 000','#a855f7','fa-piggy-bank']].map(([l,v,c,i]) => `
    <div class="card p-4"><div class="flex items-center justify-between mb-2"><span class="text-xs text-slate-500">${l}</span><i class="fas ${i}" style="color:${c}"></i></div><div class="text-xl font-800 text-white">${v}</div><div class="text-xs mt-0.5" style="color:${c}">FCFA</div></div>`).join('')}
  </div>
  <div class="card p-6">
    <div class="flex items-center justify-between mb-4"><h3 class="font-700 text-white">Dépenses par Chantier</h3></div>
    <div class="space-y-3">
      ${[['Villa Zone 1',45,30.6,68,'#f97316'],['Maison R+1',28,9.8,35,'#3b82f6'],['Commerce Gounghin',18,14.7,82,'#22c55e'],['Villa Bobo',54,10.8,20,'#ef4444']].map(([n,t,s,p,c]) => `
      <div>
        <div class="flex items-center justify-between mb-1 text-xs"><span class="text-slate-300 font-500">${n}</span><span class="text-slate-400">${s}M / ${t}M FCFA</span></div>
        <div class="flex items-center gap-2"><div class="progress-bar h-4 flex-1"><div class="progress-fill h-full rounded-md" style="width:${p}%;background:${c}"></div></div><span class="text-xs font-700" style="color:${c}">${p}%</span></div>
      </div>`).join('')}
    </div>
  </div>
  <div class="card p-6">
    <div class="flex items-center justify-between mb-5"><h3 class="font-700 text-white">Dépenses Récentes</h3><button onclick="openModal('modal-dep')" class="btn-primary text-sm py-2 px-4"><i class="fas fa-plus"></i> Ajouter</button></div>
    <table class="w-full">
      <thead><tr class="border-b border-white/5"><th class="text-left py-2 px-3 text-xs text-slate-500">DATE</th><th class="text-left py-2 px-3 text-xs text-slate-500">DESCRIPTION</th><th class="text-left py-2 px-3 text-xs text-slate-500">MONTANT</th><th class="text-left py-2 px-3 text-xs text-slate-500">STATUT</th><th class="py-2 px-3"></th></tr></thead>
      <tbody>
        ${[['16/05','Achat 50 sacs ciment','600 000','approved'],['15/05','Paiement maçons','1 200 000','pending'],['14/05','Fer à béton HA12','2 100 000','flagged'],['13/05','Transport gravier','280 000','approved']].map(([d,desc,amt,s]) => `
        <tr class="table-row">
          <td class="py-3 px-3 text-xs text-slate-500">${d} mai</td>
          <td class="py-3 px-3 text-sm text-white font-500">${desc}</td>
          <td class="py-3 px-3 text-sm font-700 text-white">${amt} FCFA</td>
          <td class="py-3 px-3"><span class="badge ${s==='approved'?'badge-success':s==='pending'?'badge-warning':'badge-danger'}">${s==='approved'?'Approuvé':s==='pending'?'En attente':'Signalé'}</span></td>
          <td class="py-3 px-3">${s==='pending'?`<button onclick="showToast('Dépense approuvée','success')" class="text-xs text-green-400">Approuver</button>`:''}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>
</main></div></div>
<div id="modal-dep" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4" style="background:rgba(0,0,0,.7);backdrop-filter:blur(8px)">
  <div class="card w-full max-w-md animate-fade-in">
    <div class="flex items-center justify-between p-5 border-b border-white/5"><h3 class="font-700 text-white">Nouvelle Dépense</h3><button onclick="closeModal('modal-dep')" class="text-slate-400 hover:text-white"><i class="fas fa-times"></i></button></div>
    <div class="p-5 space-y-4">
      <div><label class="text-xs text-slate-400 mb-1 block">Chantier</label><select class="input"><option>Villa Zone 1</option><option>Maison R+1</option></select></div>
      <div><label class="text-xs text-slate-400 mb-1 block">Catégorie</label><select class="input"><option>Matériaux</option><option>Main d'oeuvre</option><option>Transport</option></select></div>
      <div><label class="text-xs text-slate-400 mb-1 block">Description</label><input type="text" placeholder="Ex: Achat 50 sacs ciment" class="input"/></div>
      <div><label class="text-xs text-slate-400 mb-1 block">Montant (FCFA)</label><input type="number" placeholder="600000" class="input"/></div>
      <div class="flex gap-3"><button onclick="closeModal('modal-dep')" class="btn-secondary flex-1 justify-center">Annuler</button><button onclick="showToast('Dépense enregistrée','success');closeModal('modal-dep')" class="btn-primary flex-1 justify-center">Enregistrer</button></div>
    </div>
  </div>
</div>`)
}

function approvPage() {
  return shell('Approvisionnements', `<div class="flex">${sidebar('/approvisionnements')}<div class="main-content flex-1">${topbar('Approvisionnements','Module Anti-Vol — Photo + GPS obligatoires')}<main class="p-6 animate-fade-in space-y-6">
  <div class="p-4 rounded-2xl flex items-center gap-4" style="background:linear-gradient(135deg,rgba(249,115,22,.12),rgba(234,88,12,.06));border:1px solid rgba(249,115,22,.25)">
    <div class="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 bg-orange-500/20"><i class="fas fa-shield-check text-orange-400 text-xl"></i></div>
    <div><div class="font-700 text-white">Module Anti-Vol Actif</div><div class="text-sm text-slate-400">Chaque livraison requiert une photo + géolocalisation + validation contrôleur. 48 livraisons sécurisées.</div></div>
    <div class="ml-auto text-right flex-shrink-0"><div class="text-2xl font-900 text-green-400">98%</div><div class="text-xs text-slate-500">Taux validation</div></div>
  </div>
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    ${[['Total','48','fa-truck-ramp-box','#f97316'],['Validées','45','fa-circle-check','#22c55e'],['En attente','2','fa-clock','#eab308'],['Signalées','1','fa-flag','#ef4444']].map(([l,v,i,c]) => `
    <div class="card p-4 flex items-center gap-3"><div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style="background:${c}20"><i class="fas ${i}" style="color:${c}"></i></div><div><div class="text-xl font-800 text-white">${v}</div><div class="text-xs text-slate-500">${l}</div></div></div>`).join('')}
  </div>
  <div class="card p-6">
    <div class="flex items-center justify-between mb-4"><h3 class="font-700 text-white">Historique Livraisons</h3><button onclick="openModal('modal-liv')" class="btn-primary text-sm py-2 px-4"><i class="fas fa-plus"></i> Enregistrer</button></div>
    <table class="w-full">
      <thead><tr class="border-b border-white/5"><th class="text-left py-2 px-3 text-xs text-slate-500">MATÉRIAU</th><th class="text-left py-2 px-3 text-xs text-slate-500">QTÉ</th><th class="text-left py-2 px-3 text-xs text-slate-500">PRIX UNIT.</th><th class="text-left py-2 px-3 text-xs text-slate-500">TOTAL</th><th class="text-left py-2 px-3 text-xs text-slate-500">📷</th><th class="text-left py-2 px-3 text-xs text-slate-500">📍</th><th class="text-left py-2 px-3 text-xs text-slate-500">STATUT</th></tr></thead>
      <tbody>
        ${[['Ciment Portland','50 sacs','12 000','600 000',true,true,'validated',false],['Sable fin','5 m³','35 000','175 000',true,true,'validated',false],['Fer HA12','500 kg','4 200','2 100 000',true,false,'flagged',true],['Briques rouges','500 u','200','100 000',true,true,'validated',false],['Ciment (susp.)','30 sacs','18 000','540 000',false,false,'pending',true]].map(([m,q,pu,tot,ph,gps,s,anom]) => `
        <tr class="table-row ${anom?'bg-red-500/3':''}">
          <td class="py-3 px-3"><div class="font-600 text-sm text-white flex items-center gap-2">${anom?'<i class="fas fa-exclamation-triangle text-red-400 text-xs"></i>':''}${m}</div></td>
          <td class="py-3 px-3 text-sm text-white">${q}</td>
          <td class="py-3 px-3 text-xs ${anom?'text-red-400 font-700':'text-slate-300'}">${pu} FCFA</td>
          <td class="py-3 px-3 text-sm font-700 text-white">${tot} FCFA</td>
          <td class="py-3 px-3 text-center">${ph?'<i class="fas fa-image text-green-400"></i>':'<i class="fas fa-image text-red-400/50"></i>'}</td>
          <td class="py-3 px-3 text-center">${gps?'<i class="fas fa-location-dot text-green-400"></i>':'<i class="fas fa-location-dot text-red-400/50"></i>'}</td>
          <td class="py-3 px-3"><span class="badge ${s==='validated'?'badge-success':s==='pending'?'badge-warning':'badge-danger'}">${s==='validated'?'Validée':s==='pending'?'En attente':'Signalée'}</span></td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>
</main></div></div>
<div id="modal-liv" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4" style="background:rgba(0,0,0,.7);backdrop-filter:blur(8px)">
  <div class="card w-full max-w-lg animate-fade-in max-h-[90vh] overflow-y-auto">
    <div class="flex items-center justify-between p-5 border-b border-white/5"><div><h3 class="font-700 text-white">Nouvelle Livraison</h3><p class="text-xs text-slate-500">Photo + GPS obligatoires</p></div><button onclick="closeModal('modal-liv')" class="text-slate-400 hover:text-white"><i class="fas fa-times"></i></button></div>
    <div class="p-5 space-y-4">
      <div class="grid grid-cols-2 gap-3">
        <div class="col-span-2"><label class="text-xs text-slate-400 mb-1 block">Matériau *</label><select class="input"><option>Ciment</option><option>Sable</option><option>Gravier</option><option>Fer à béton</option><option>Briques</option></select></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Quantité *</label><input type="number" class="input" placeholder="50"/></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Prix unitaire (FCFA)</label><input type="number" class="input" placeholder="12000"/></div>
      </div>
      <div><label class="text-xs text-slate-400 mb-1.5 block font-500">📸 Photo livraison <span class="text-red-400">*</span></label><div class="border-2 border-dashed border-orange-500/40 rounded-xl p-5 text-center cursor-pointer hover:border-orange-500/70 hover:bg-orange-500/5 transition-all"><i class="fas fa-camera text-3xl text-orange-500/60 mb-2 block"></i><div class="text-sm text-slate-300">Prendre ou uploader une photo</div></div></div>
      <div class="flex items-center gap-3 p-3 rounded-lg bg-green-500/5 border border-green-500/20"><i class="fas fa-location-dot text-green-400"></i><div class="text-xs text-slate-300">GPS automatique activé<br><span class="text-slate-500">Ouagadougou, 12.36° N, 1.54° W</span></div><span class="ml-auto badge badge-success">GPS OK</span></div>
      <div class="flex gap-3"><button onclick="closeModal('modal-liv')" class="btn-secondary flex-1 justify-center">Annuler</button><button onclick="showToast('Livraison enregistrée, en attente de validation');closeModal('modal-liv')" class="btn-primary flex-1 justify-center"><i class="fas fa-truck"></i> Enregistrer</button></div>
    </div>
  </div>
</div>`)
}

function materiauxPage() {
  return shell('Matériaux & Stock', `<div class="flex">${sidebar('/materiaux')}<div class="main-content flex-1">${topbar('Matériaux & Stock','Inventaire en temps réel')}<main class="p-6 animate-fade-in space-y-6">
  <div class="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
    ${[['Ciment',35,200,'sacs','#f97316','fa-bag-shopping',false],['Sable',5,15,'m³','#eab308','fa-hill-rockslide',false],['Fer à béton',0.2,2.5,'tonnes','#ef4444','fa-ruler-horizontal',true],['Briques',1200,3000,'u','#a855f7','fa-bricks',false],['Gravier',3,12,'m³','#3b82f6','fa-circle-dot',false],['Peinture',20,60,'bidons','#22c55e','fa-paintbrush',false],['Bois',50,120,'ml','#a3855f','fa-tree',false],['Carreaux',0,200,'m²','#6b7280','fa-th-large',false]].map(([n,q,t,u,c,i,danger]) => {
      const pct=Math.round(Number(q)/Number(t)*100);
      return `<div class="card p-5 ${danger?'border border-red-500/25':''}">
        ${danger?'<div class="flex items-center gap-1 mb-2 text-xs text-red-400"><i class="fas fa-exclamation-triangle"></i> Stock critique !</div>':''}
        <div class="flex items-center gap-2 mb-3"><div class="w-9 h-9 rounded-lg flex items-center justify-center" style="background:${c}20"><i class="fas ${i} text-sm" style="color:${c}"></i></div><div class="font-700 text-sm text-white">${n}</div></div>
        <div class="text-2xl font-900 text-white mb-0.5">${q}<span class="text-sm font-400 text-slate-500 ml-1">${u}</span></div>
        <div class="text-xs text-slate-600 mb-3">sur ${t} ${u} reçus</div>
        <div class="progress-bar h-2"><div class="progress-fill" style="width:${pct}%;background:${danger?'#ef4444':c}"></div></div>
        <div class="flex items-center justify-between text-xs mt-2"><span style="color:${c}">${pct}% restant</span></div>
      </div>`}).join('')}
  </div>
</main></div></div>`)
}

function journalPage() {
  return shell('Journal de Chantier', `<div class="flex">${sidebar('/journal')}<div class="main-content flex-1">${topbar('Journal de Chantier','Historique chronologique')}<main class="p-6 animate-fade-in space-y-6">
  <div class="flex items-center justify-between"><div class="flex gap-2">${['Tous','Rapports','Incidents','Progrès'].map((f,i)=>`<button class="${i===0?'btn-primary':'btn-secondary'} text-sm py-2 px-4">${f}</button>`).join('')}</div><button onclick="openModal('modal-je')" class="btn-primary"><i class="fas fa-plus"></i> Nouvelle entrée</button></div>
  <div class="relative"><div class="absolute left-6 top-0 bottom-0 w-px bg-white/8"></div>
  <div class="space-y-5 pl-14">
    ${[
      {type:'progress',icon:'fa-chart-line',color:'#22c55e',title:'Rapport quotidien — 16 Mai',content:'Gros œuvre 3ème niveau en cours. 8 maçons sur le chantier. Pose des fers d\'attente terminée côté Est.',author:'Ibrahim Kaboré',role:'Contrôleur',workers:8,pct:68,weather:'☀️'},
      {type:'incident',icon:'fa-triangle-exclamation',color:'#ef4444',title:'Incident — Pénurie ciment',content:'Stock de ciment épuisé. Travaux suspendus à 15h. Commande urgente passée chez CBMP. Livraison prévue demain.',author:'Awa Traoré',role:'Maçonne',workers:6,pct:null,weather:'⛅'},
      {type:'note',icon:'fa-sticky-note',color:'#a855f7',title:'Note propriétaire',content:'Suite à l\'alerte de l\'IA sur le prix du fer, j\'ai contacté 3 fournisseurs. Changement de fournisseur validé.',author:'Kofi Sawadogo',role:'Propriétaire',workers:null,pct:null,weather:null},
    ].map(e => `
    <div class="relative">
      <div class="absolute -left-8 w-4 h-4 rounded-full border-2 border-dark-900" style="background:${e.color}"></div>
      <div class="card p-5">
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0" style="background:${e.color}18"><i class="fas ${e.icon}" style="color:${e.color}"></i></div>
            <div><div class="font-700 text-white text-sm">${e.title}</div><div class="text-xs text-slate-500">2025</div></div>
          </div>
          <div class="flex items-center gap-2">${e.weather?`<span>${e.weather}</span>`:''} ${e.workers?`<span class="badge badge-info"><i class="fas fa-users mr-1"></i>${e.workers}</span>`:''} ${e.pct?`<span class="badge badge-orange">${e.pct}%</span>`:''}</div>
        </div>
        <p class="text-sm text-slate-300 leading-relaxed mb-3">${e.content}</p>
        <div class="flex items-center gap-2 pt-3 border-t border-white/5">
          <div class="w-6 h-6 rounded-full bg-orange-500/25 flex items-center justify-center text-xs font-700 text-orange-400">${e.author.split(' ').map((n:string)=>n[0]).join('')}</div>
          <span class="text-xs text-slate-400">${e.author} · ${e.role}</span>
        </div>
      </div>
    </div>`).join('')}
  </div></div>
</main></div></div>
<div id="modal-je" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4" style="background:rgba(0,0,0,.7);backdrop-filter:blur(8px)">
  <div class="card w-full max-w-lg animate-fade-in">
    <div class="flex items-center justify-between p-5 border-b border-white/5"><h3 class="font-700 text-white">Nouvelle entrée</h3><button onclick="closeModal('modal-je')" class="text-slate-400 hover:text-white"><i class="fas fa-times"></i></button></div>
    <div class="p-5 space-y-4">
      <div><label class="text-xs text-slate-400 mb-1 block">Type</label><select class="input"><option>Rapport quotidien</option><option>Incident</option><option>Progrès</option><option>Note</option></select></div>
      <div><label class="text-xs text-slate-400 mb-1 block">Titre</label><input type="text" class="input" placeholder="Titre de l'entrée"/></div>
      <div><label class="text-xs text-slate-400 mb-1 block">Contenu</label><textarea rows="4" class="input resize-none" placeholder="Décrivez ce qui s'est passé..."></textarea></div>
      <div class="grid grid-cols-2 gap-3"><div><label class="text-xs text-slate-400 mb-1 block">Ouvriers</label><input type="number" class="input" placeholder="8"/></div><div><label class="text-xs text-slate-400 mb-1 block">Avancement %</label><input type="number" class="input" placeholder="68" min="0" max="100"/></div></div>
      <div class="flex gap-3"><button onclick="closeModal('modal-je')" class="btn-secondary flex-1 justify-center">Annuler</button><button onclick="showToast('Entrée publiée dans le journal');closeModal('modal-je')" class="btn-primary flex-1 justify-center">Publier</button></div>
    </div>
  </div>
</div>`)
}

function alertesPage() {
  return shell('Alertes & IA', `<div class="flex">${sidebar('/alertes')}<div class="main-content flex-1">${topbar('Alertes & IA','Détection intelligente des anomalies')}<main class="p-6 animate-fade-in space-y-6">
  <div class="grid lg:grid-cols-4 gap-4">
    <div class="card p-5 text-center" style="border:1px solid rgba(234,179,8,.3)"><div class="text-xs text-slate-500 mb-1">Score Risque Global</div><div class="text-5xl font-900 text-yellow-400 mb-1">24</div><div class="text-xs text-slate-500 mb-3">/100</div><div class="badge badge-warning mx-auto">RISQUE MODÉRÉ</div></div>
    ${[['Alertes critiques','1','#ef4444','fa-circle-xmark'],['Importantes','2','#eab308','fa-triangle-exclamation'],['Informations','5','#3b82f6','fa-circle-info']].map(([l,v,c,i]) => `
    <div class="card p-5 flex flex-col justify-between"><div class="flex items-center justify-between mb-3"><span class="text-xs text-slate-500">${l}</span><i class="fas ${i}" style="color:${c}"></i></div><div class="text-4xl font-900" style="color:${c}">${v}</div><div class="text-xs text-slate-600">alertes actives</div></div>`).join('')}
  </div>
  <div class="space-y-3">
    ${[
      {sev:'critical',icon:'fa-triangle-exclamation',color:'#ef4444',title:'Prix anormal — Ciment',desc:'Ciment commandé à 18 000 FCFA/sac (marché: 12 000 FCFA). Différence: +38%. Anomalie détectée par l\'IA.',project:'Villa Bobo-Dioulasso',time:'12 min',read:false},
      {sev:'warning',icon:'fa-boxes-stacked',color:'#eab308',title:'Stock de fer critique',desc:'Fer HA12 à 200 kg restant. Seuil critique: 500 kg. Rupture estimée dans 48h au rythme actuel.',project:'Villa Zone 1',time:'1h',read:false},
      {sev:'warning',icon:'fa-clock',color:'#f97316',title:'Livraison non validée 48h',desc:'Livraison de 30 sacs de ciment du 14/05 sans photo ni GPS. Fraude potentielle.',project:'Maison R+1 Pissy',time:'3h',read:true},
      {sev:'info',icon:'fa-check-circle',color:'#22c55e',title:'Rapport hebdomadaire disponible',desc:'Votre rapport du 10-16 Mai 2025 est prêt. Téléchargez en PDF ou partagez par WhatsApp.',project:'Tous les chantiers',time:'8h',read:true},
    ].map(a => `
    <div class="card p-5 ${!a.read?'border-l-2':''}">
      <div class="flex items-start gap-4">
        <div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style="background:${a.color}18;border:1px solid ${a.color}40"><i class="fas ${a.icon}" style="color:${a.color}"></i></div>
        <div class="flex-1 min-w-0">
          <div class="flex items-start justify-between gap-2 mb-1">
            <div class="font-700 text-white text-sm flex items-center gap-2">${!a.read?`<div class="w-2 h-2 rounded-full flex-shrink-0" style="background:${a.color}"></div>`:''}${a.title}</div>
            <span class="text-xs text-slate-600 flex-shrink-0">${a.time}</span>
          </div>
          <p class="text-sm text-slate-400 leading-relaxed mb-2">${a.desc}</p>
          <div class="flex items-center justify-between">
            <div class="text-xs text-slate-500"><i class="fas fa-hard-hat text-orange-400 mr-1"></i>${a.project}</div>
            ${a.sev==='critical'?`<button onclick="showToast('Alerte traitée','success')" class="btn-secondary text-xs py-1.5 px-3">Traiter</button>`:a.sev==='warning'?`<button onclick="showToast('Commande passée','success')" class="btn-primary text-xs py-1.5 px-3">Agir</button>`:''}
          </div>
        </div>
      </div>
    </div>`).join('')}
  </div>
  <div class="card p-6" style="background:linear-gradient(135deg,rgba(168,85,247,.07),rgba(59,130,246,.07));border:1px solid rgba(168,85,247,.2)">
    <div class="flex items-center gap-3 mb-4"><div class="w-10 h-10 rounded-xl bg-purple-500/20 flex items-center justify-center"><i class="fas fa-robot text-purple-400"></i></div><div><h3 class="font-700 text-white">Recommandations IA</h3><p class="text-xs text-slate-500">Générées automatiquement</p></div></div>
    <div class="grid md:grid-cols-3 gap-4">
      ${[['fa-magnifying-glass-dollar','#ef4444','Vérifier le fournisseur','Demandez une facture officielle pour le ciment à 18 000 FCFA/sac.'],['fa-truck-fast','#eab308','Commander du fer urgent','Rupture de stock HA12 estimée dans 48h. Commandez 2 tonnes.'],['fa-user-shield','#22c55e','Valider la livraison','30 sacs du 14/05 sans photo doivent être vérifiés physiquement.']].map(([i,c,t,d]) => `
      <div class="bg-white/[0.04] rounded-xl p-4"><div class="w-8 h-8 rounded-lg flex items-center justify-center mb-3" style="background:${c}20"><i class="fas ${i} text-xs" style="color:${c}"></i></div><div class="font-600 text-sm text-white mb-1">${t}</div><div class="text-xs text-slate-400 leading-relaxed">${d}</div></div>`).join('')}
    </div>
  </div>
</main></div></div>`)
}

function rapportsPage() {
  return shell('Rapports', `<div class="flex">${sidebar('/rapports')}<div class="main-content flex-1">${topbar('Rapports','Génération et export')}<main class="p-6 animate-fade-in space-y-6">
  <div class="grid md:grid-cols-3 gap-5">
    ${[['fa-file-chart-column','#f97316','Rapport Financier','Dépenses, budget, projections, anomalies IA','PDF · Excel'],['fa-hard-hat','#3b82f6','Rapport de Chantier','Avancement, matériaux, incidents, journal','PDF'],['fa-truck-ramp-box','#22c55e','Rapport Anti-Vol','Livraisons, validations, score de risque','PDF · WhatsApp']].map(([i,c,t,d,b]) => `
    <div class="card p-6 text-center"><div class="w-14 h-14 rounded-2xl mx-auto mb-4 flex items-center justify-center" style="background:${c}20"><i class="fas ${i} text-2xl" style="color:${c}"></i></div><h3 class="font-700 text-white mb-2">${t}</h3><p class="text-xs text-slate-500 leading-relaxed mb-4">${d}</p><div class="badge badge-info mb-4">${b}</div><button onclick="showToast('Rapport en cours de génération...')" class="btn-primary w-full justify-center"><i class="fas fa-download"></i> Générer</button></div>`).join('')}
  </div>
  <div class="card p-6">
    <h3 class="font-700 text-white mb-4">Rapports Récents</h3>
    <div class="space-y-3">
      ${[['Rapport Financier Hebdo — 10-16 Mai 2025','2.4 MB','PDF','16/05'],['Rapport Chantier — Villa Zone 1','5.1 MB','PDF','14/05'],['Rapport Anti-Vol — Avril 2025','1.8 MB','PDF','01/05'],['Rapport Financier Mensuel — Avril','3.2 MB','Excel','30/04']].map(([n,s,t,d]) => `
    <div class="flex items-center gap-4 p-3 rounded-xl bg-white/[0.03] hover:bg-white/[0.06] cursor-pointer transition-all">
      <div class="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0" style="background:${t==='PDF'?'rgba(239,68,68,.15)':'rgba(34,197,94,.15)'}"><i class="fas fa-file-${t==='PDF'?'pdf':'excel'} text-lg" style="color:${t==='PDF'?'#ef4444':'#22c55e'}"></i></div>
      <div class="flex-1"><div class="font-600 text-sm text-white">${n}</div><div class="text-xs text-slate-500">${d} · ${s}</div></div>
      <div class="flex gap-2">
        <button onclick="showToast('Téléchargement démarré')" class="btn-secondary text-xs py-1.5 px-3"><i class="fas fa-download"></i></button>
        <button onclick="showToast('Partagé par WhatsApp','success')" class="btn-secondary text-xs py-1.5 px-3"><i class="fab fa-whatsapp text-green-400"></i></button>
      </div>
    </div>`).join('')}
    </div>
  </div>
</main></div></div>`)
}

function abonnementsPage() {
  return shell('Abonnements', `<div class="flex">${sidebar('/abonnements')}<div class="main-content flex-1">${topbar('Abonnements','Gérez votre formule FasoChantier')}<main class="p-6 animate-fade-in space-y-8">
  <div class="card p-6" style="border:1px solid rgba(249,115,22,.3)">
    <div class="flex items-start justify-between">
      <div><div class="badge badge-orange mb-2">FORMULE ACTUELLE</div><h2 class="text-2xl font-800 text-white flex items-center gap-2"><i class="fas fa-rocket text-orange-400"></i> Plan Pro</h2><p class="text-slate-400 text-sm mt-1">100 000 FCFA / chantier · Actif jusqu'au 31 Déc 2025</p></div>
      <div class="text-right"><div class="text-3xl font-900 grad-text">100k</div><div class="text-xs text-slate-500">FCFA / chantier</div></div>
    </div>
  </div>
  <div><h2 class="text-xl font-800 text-white mb-6 text-center">Choisissez votre formule</h2>
  <div class="grid md:grid-cols-3 gap-6">
    ${[
      {name:'Basic',price:'50 000',icon:'fa-seedling',color:'#94a3b8',features:['1 chantier','2 utilisateurs','Suivi budget','Module anti-vol','Photos illimitées'],popular:false,current:false},
      {name:'Pro',price:'100 000',icon:'fa-rocket',color:'#f97316',features:['10 chantiers','Illimité users','IA anomalies','Rapports PDF','Alertes WhatsApp','Mode diaspora'],popular:true,current:true},
      {name:'Entreprise',price:'Sur devis',icon:'fa-building',color:'#a855f7',features:['Chantiers illimités','API complète','Caméra IA','Support 24/7','Formation équipe'],popular:false,current:false},
    ].map(p => `
    <div class="card p-6 relative ${p.popular?'border-2':''}">
      ${p.popular?'<div class="absolute -top-3 left-1/2 -translate-x-1/2 badge badge-orange px-4 py-1">⭐ POPULAIRE</div>':''}
      ${p.current?'<div class="absolute top-4 right-4 badge badge-success">Actuel</div>':''}
      <div class="text-center mb-5"><div class="w-12 h-12 rounded-2xl mx-auto mb-3 flex items-center justify-center" style="background:${p.color}20"><i class="fas ${p.icon} text-xl" style="color:${p.color}"></i></div><h3 class="font-800 text-xl text-white">${p.name}</h3><div class="text-3xl font-900 mt-2" style="color:${p.color}">${p.price}</div><div class="text-xs text-slate-500">FCFA${p.price!=='Sur devis'?' / chantier':''}</div></div>
      <div class="space-y-2 mb-5">${p.features.map(f=>`<div class="flex items-center gap-2 text-sm"><i class="fas fa-check-circle text-xs" style="color:${p.color}"></i><span class="text-slate-300">${f}</span></div>`).join('')}</div>
      <button onclick="openModal('modal-pay')" class="${p.current?'btn-secondary':'btn-primary'} w-full justify-center">${p.current?'<i class="fas fa-check"></i> Plan actuel':p.price==='Sur devis'?'<i class="fas fa-phone"></i> Contacter':'<i class="fas fa-arrow-right"></i> Choisir'}</button>
    </div>`).join('')}
  </div></div>
  <div class="card p-5"><h3 class="font-700 text-white mb-4 text-center">Modes de paiement acceptés</h3><div class="flex flex-wrap items-center justify-center gap-4">${[['Orange Money','#ff6600'],['Moov Money','#0066cc'],['Wave','#1db7e7'],['MTN Money','#ffd700'],['Carte bancaire','#4f46e5']].map(([n,c])=>`<div class="flex items-center gap-2 px-4 py-3 rounded-xl bg-white/5 border border-white/10"><i class="fas fa-mobile-screen" style="color:${c}"></i><span class="text-sm text-slate-300 font-500">${n}</span></div>`).join('')}</div></div>
</main></div></div>
<div id="modal-pay" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4" style="background:rgba(0,0,0,.7);backdrop-filter:blur(8px)">
  <div class="card w-full max-w-md animate-fade-in">
    <div class="flex items-center justify-between p-5 border-b border-white/5"><h3 class="font-700 text-white">Paiement sécurisé</h3><button onclick="closeModal('modal-pay')" class="text-slate-400 hover:text-white"><i class="fas fa-times"></i></button></div>
    <div class="p-5 space-y-4">
      <div class="bg-orange-500/10 border border-orange-500/30 rounded-xl p-4 text-center"><div class="font-700 text-white">Plan Pro — 1 Chantier</div><div class="text-2xl font-900 text-orange-400 mt-1">100 000 FCFA</div></div>
      <div><label class="text-xs text-slate-400 mb-1 block">Mode de paiement</label><select class="input"><option>Orange Money</option><option>Moov Money</option><option>Wave</option><option>Carte bancaire</option></select></div>
      <div><label class="text-xs text-slate-400 mb-1 block">Numéro de téléphone</label><input type="tel" class="input" placeholder="70 00 00 00"/></div>
      <button onclick="showToast('Paiement initié ! Confirmez sur votre téléphone','info');closeModal('modal-pay')" class="btn-primary w-full justify-center py-3"><i class="fas fa-lock"></i> Payer 100 000 FCFA</button>
      <p class="text-xs text-slate-600 text-center">Paiement sécurisé · Remboursement sous 7 jours</p>
    </div>
  </div>
</div>`)
}

function adminPage() {
  return shell('Administration', `<div class="flex">${sidebar('/admin')}<div class="main-content flex-1">${topbar('Administration','Gestion globale de la plateforme')}<main class="p-6 animate-fade-in space-y-6">
  <div class="grid grid-cols-2 lg:grid-cols-5 gap-4">
    ${[['Utilisateurs','2 847','fa-users','#f97316'],['Chantiers actifs','438','fa-hard-hat','#22c55e'],['Revenue mensuel','43.2M FCFA','fa-sack-dollar','#3b82f6'],['Abonnements','312','fa-crown','#a855f7'],['Rétention','94%','fa-heart','#ef4444']].map(([l,v,i,c]) => `
    <div class="card p-4 text-center"><i class="fas ${i} text-2xl mb-2 block" style="color:${c}"></i><div class="text-xl font-900 text-white">${v}</div><div class="text-xs text-slate-500">${l}</div></div>`).join('')}
  </div>
  <div class="card p-6">
    <div class="flex items-center justify-between mb-4"><h3 class="font-700 text-white">Utilisateurs récents</h3><button onclick="showToast('Invitation envoyée','success')" class="btn-primary text-sm py-2 px-4"><i class="fas fa-user-plus"></i> Inviter</button></div>
    <table class="w-full">
      <thead><tr class="border-b border-white/5"><th class="text-left py-2 px-3 text-xs text-slate-500">UTILISATEUR</th><th class="text-left py-2 px-3 text-xs text-slate-500">RÔLE</th><th class="text-left py-2 px-3 text-xs text-slate-500">PLAN</th><th class="text-left py-2 px-3 text-xs text-slate-500">STATUT</th><th class="py-2 px-3"></th></tr></thead>
      <tbody>
        ${[['Kofi Sawadogo','Propriétaire','Pro',true],['Fatou Ouédraogo','Propriétaire','Basic',true],['Ibrahim Kaboré','Contrôleur','Basic',true],['Awa Traoré','Propriétaire','Pro',true],['Moussa Zongo','Tâcheron','—',false]].map(([n,r,p,a]) => `
        <tr class="table-row">
          <td class="py-3 px-3"><div class="flex items-center gap-2"><div class="w-8 h-8 rounded-full bg-gradient-to-br from-orange-500 to-orange-700 flex items-center justify-center text-xs font-700 text-white">${(n as string).split(' ').map((x:string)=>x[0]).join('').slice(0,2)}</div><div class="font-600 text-sm text-white">${n}</div></div></td>
          <td class="py-3 px-3 text-xs text-slate-400">${r}</td>
          <td class="py-3 px-3"><span class="badge ${p==='Pro'?'badge-orange':p==='Basic'?'badge-info':'badge-warning'}">${p}</span></td>
          <td class="py-3 px-3"><span class="badge ${a?'badge-success':'badge-danger'}">${a?'Actif':'Suspendu'}</span></td>
          <td class="py-3 px-3"><button onclick="showToast('Action effectuée','${a?'warning':'success'}')" class="text-xs ${a?'text-red-400':'text-green-400'}">${a?'Suspendre':'Réactiver'}</button></td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>
</main></div></div>`)
}

function profilPage(name = '', email = '', role = '') {
  const roleLabel: Record<string, string> = { owner: 'Propriétaire', controller: 'Contrôleur', worker: 'Tâcheron', admin: 'Administrateur' }
  const initials = name.split(' ').map((n: string) => n[0]).join('').slice(0, 2).toUpperCase() || '?'
  return shell('Mon Profil', `<div class="flex">${sidebar('/profil')}<div class="main-content flex-1">${topbar('Mon Profil','Paramètres et préférences')}<main class="p-6 animate-fade-in space-y-6">
  <div class="card p-6">
    <div class="flex flex-wrap items-center gap-6">
      <div class="relative">
        <div class="w-20 h-20 rounded-2xl bg-gradient-to-br from-orange-500 to-orange-700 flex items-center justify-center text-white text-2xl font-900 shadow-xl">${initials}</div>
        <button class="absolute -bottom-2 -right-2 w-8 h-8 rounded-full bg-orange-500 flex items-center justify-center text-white text-xs shadow-lg"><i class="fas fa-camera"></i></button>
      </div>
      <div>
        <h2 class="text-2xl font-800 text-white">${name || 'Utilisateur'}</h2>
        <p class="text-slate-400 text-sm">${roleLabel[role] || role || 'Utilisateur'} · <span class="text-orange-400">Plan Pro</span></p>
        <div class="text-xs text-slate-500 mt-1"><i class="fas fa-envelope mr-1"></i>${email}</div>
      </div>
      <div class="ml-auto"><button onclick="showToast('Profil enregistré !','success')" class="btn-primary"><i class="fas fa-save"></i> Enregistrer</button></div>
    </div>
  </div>
  <div class="grid lg:grid-cols-2 gap-6">
    <div class="card p-6">
      <h3 class="font-700 text-white mb-4">Informations Personnelles</h3>
      <div class="space-y-4">
        <div class="grid grid-cols-2 gap-3">
          <div><label class="text-xs text-slate-400 mb-1 block">Prénom</label><input type="text" value="${name.split(' ')[0]||''}" class="input"/></div>
          <div><label class="text-xs text-slate-400 mb-1 block">Nom</label><input type="text" value="${name.split(' ').slice(1).join(' ')||''}" class="input"/></div>
        </div>
        <div><label class="text-xs text-slate-400 mb-1 block">Email</label><input type="email" value="${email}" class="input"/></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Téléphone WhatsApp</label><input type="tel" class="input" placeholder="+226 70 00 00 00"/></div>
        <div><label class="text-xs text-slate-400 mb-1 block">Pays</label><select class="input"><option>🇧🇫 Burkina Faso</option><option>🇫🇷 France</option><option>🇺🇸 USA</option></select></div>
        <label class="flex items-center gap-2 cursor-pointer"><input type="checkbox" class="w-4 h-4 accent-orange-500"/><span class="text-sm text-slate-300">Mode Diaspora</span></label>
      </div>
    </div>
    <div class="space-y-5">
      <div class="card p-6">
        <h3 class="font-700 text-white mb-4">Notifications</h3>
        <div class="space-y-3">
          ${[['Alertes budget','checked'],['Livraisons à valider','checked'],['Anomalies IA','checked'],['Rapports hebdo','checked'],['Actualités','']].map(([l,c]) => `
          <div class="flex items-center justify-between"><span class="text-sm text-slate-300">${l}</span><label class="relative inline-flex cursor-pointer"><input type="checkbox" ${c} class="sr-only peer"><div class="w-10 h-5 bg-white/10 rounded-full peer peer-checked:bg-orange-500 transition-colors"></div><div class="absolute left-0.5 top-0.5 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-5"></div></label></div>`).join('')}
        </div>
      </div>
      <div class="card p-6">
        <h3 class="font-700 text-white mb-4">Sécurité</h3>
        <div class="space-y-3">
          <button onclick="showToast('Lien de changement envoyé par email','info')" class="btn-secondary w-full justify-center text-sm"><i class="fas fa-lock"></i> Changer le mot de passe</button>
          <button onclick="showToast('2FA activée avec succès','success')" class="btn-secondary w-full justify-center text-sm"><i class="fas fa-mobile-screen"></i> Activer la 2FA</button>
          <button onclick="doLogout()" class="btn-secondary w-full justify-center text-sm text-red-400 hover:bg-red-500/10"><i class="fas fa-right-from-bracket"></i> Se déconnecter</button>
        </div>
      </div>
    </div>
  </div>
</main></div></div>
<script>async function doLogout(){await fetch('/api/auth/logout',{method:'POST'});window.location.href='/login?msg=logged_out';}</script>`)
}

export default app
