'use strict';
const fs   = require('fs');
const path = require('path');
const OUT  = path.join(__dirname, 'wireframes');

// ════════════════════════════════════════════════════════════════════
// SECTION 1 — DESIGN TOKENS  (3-layer: primitive → semantic → component)
// ════════════════════════════════════════════════════════════════════
const BASE_CSS = `
@import url('https://fonts.googleapis.com/css2?family=Lora:wght@400;500;600;700&family=Nunito+Sans:wght@300;400;500;600;700&display=swap');

/* ── LAYER 1: Primitive tokens ──────────────────────────────────── */
:root {
  /* Green scale (primary brand: organic farm) */
  --prim-green-50:  #eef7e8; --prim-green-100: #d4ecbf;
  --prim-green-200: #b0da8f; --prim-green-300: #87c65c;
  --prim-green-400: #65b133; --prim-green-500: #4d9620;
  --prim-green-600: #3d7a18; --prim-green-700: #2f5f12;
  --prim-green-800: #22450d; --prim-green-900: #162d08;
  /* Warm (earth/soil/straw) */
  --prim-warm-50:  #faf8f2; --prim-warm-100: #f2ede0;
  --prim-warm-200: #e4d9c4; --prim-warm-300: #d0bfa0;
  --prim-warm-400: #b59e7a; --prim-warm-500: #957d58;
  /* Gray */
  --prim-gray-50:  #f9fafb; --prim-gray-100: #f3f4f6;
  --prim-gray-200: #e5e7eb; --prim-gray-300: #d1d5db;
  --prim-gray-400: #9ca3af; --prim-gray-500: #6b7280;
  --prim-gray-600: #4b5563; --prim-gray-700: #374151;
  --prim-gray-800: #1f2937; --prim-gray-900: #111827;
  /* Spacing raw (8-pt base) */
  --sp-1:4px; --sp-2:8px; --sp-3:12px; --sp-4:16px;
  --sp-5:20px; --sp-6:24px; --sp-7:28px; --sp-8:32px;
  --sp-10:40px; --sp-12:48px; --sp-16:64px; --sp-20:80px;
  /* Typography raw */
  --fz-xs:11px; --fz-sm:12px; --fz-base:14px; --fz-md:15px;
  --fz-lg:16px; --fz-xl:18px; --fz-2xl:20px; --fz-3xl:24px;
  --fz-4xl:28px; --fz-5xl:32px; --fz-6xl:40px; --fz-7xl:48px;
  /* Radii raw */
  --r-sm:4px; --r-md:8px; --r-lg:12px; --r-xl:16px;
  --r-2xl:20px; --r-full:9999px;
  /* Shadows raw */
  --sh-xs: 0 1px 2px rgba(0,0,0,.04);
  --sh-sm: 0 1px 3px rgba(0,0,0,.07), 0 1px 2px rgba(0,0,0,.05);
  --sh-md: 0 4px 8px rgba(0,0,0,.07), 0 2px 4px rgba(0,0,0,.05);
  --sh-lg: 0 10px 24px rgba(0,0,0,.08), 0 4px 8px rgba(0,0,0,.04);
}

/* ── LAYER 2: Semantic tokens ────────────────────────────────────── */
:root {
  --color-bg:           var(--prim-warm-50);
  --color-surface:      #ffffff;
  --color-surface-alt:  var(--prim-warm-100);
  --color-surface-2:    var(--prim-green-50);
  --color-border:       var(--prim-warm-200);
  --color-border-subtle:var(--prim-warm-100);
  --color-primary:      var(--prim-green-700);
  --color-primary-dark: var(--prim-green-800);
  --color-primary-light:var(--prim-green-400);
  --color-primary-bg:   var(--prim-green-50);
  --color-accent:       var(--prim-green-400);
  --color-text:         var(--prim-gray-900);
  --color-text-2:       var(--prim-gray-600);
  --color-text-muted:   var(--prim-gray-400);
  --color-text-on-primary: #ffffff;
  --color-sidebar-bg:   var(--prim-green-900);
  --color-sidebar-text: #cde8b6;
  --color-sidebar-hover: rgba(255,255,255,.07);
  --color-sidebar-active:#2f5f12;
  --color-img-bg:       var(--prim-warm-200);
  --color-img-text:     var(--prim-warm-500);
  --color-status-ok:    #16a34a; --color-status-ok-bg:   #dcfce7;
  --color-status-warn:  #d97706; --color-status-warn-bg: #fef3c7;
  --color-status-err:   #dc2626; --color-status-err-bg:  #fee2e2;
  --color-status-info:  #2563eb; --color-status-info-bg: #dbeafe;
  /* Spacing semantic (8-pt grid) */
  --s1:8px;  --s2:16px; --s3:24px; --s4:32px;
  --s5:40px; --s6:48px; --s7:56px; --s8:64px; --s10:80px;
  /* Typography semantic */
  --font-display: 'Lora', Georgia, serif;
  --font-body:    'Nunito Sans', 'Segoe UI', sans-serif;
  --text-caption: var(--fz-xs);
  --text-label:   var(--fz-sm);
  --text-body:    var(--fz-base);
  --text-body-lg: var(--fz-md);
  --text-ui:      var(--fz-lg);
  --text-h5:      var(--fz-xl);
  --text-h4:      var(--fz-2xl);
  --text-h3:      var(--fz-3xl);
  --text-h2:      var(--fz-4xl);
  --text-h1:      var(--fz-5xl);
  --text-hero:    var(--fz-6xl);
  /* Layout */
  --sidebar-w:     280px;
  --sidebar-w-sm:  64px;
  --topbar-h:      64px;
  --content-max:   1160px;
}

/* ── LAYER 3: Component tokens ───────────────────────────────────── */
:root {
  --btn-radius:      var(--r-md);
  --btn-h:           40px;
  --btn-h-sm:        32px;
  --btn-h-lg:        48px;
  --btn-px:          var(--s2);
  --btn-px-lg:       var(--s3);
  --btn-font:        var(--font-body);
  --btn-fz:          var(--fz-base);
  --btn-fw:          600;
  --input-bg:        var(--color-surface);
  --input-border:    var(--color-border);
  --input-focus:     var(--color-primary);
  --input-h:         40px;
  --input-h-lg:      48px;
  --input-px:        var(--s2);
  --input-radius:    var(--r-md);
  --input-fz:        var(--fz-base);
  --card-bg:         var(--color-surface);
  --card-border:     var(--color-border);
  --card-radius:     var(--r-lg);
  --card-shadow:     var(--sh-sm);
  --card-p:          var(--s3);
  --card-img-radius: var(--r-md);
}

/* ── GLOBAL RESET & BASE ─────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px;-webkit-font-smoothing:antialiased}
body{font-family:var(--font-body);font-size:var(--text-body);
  color:var(--color-text);background:var(--color-bg);min-width:1440px}
a{text-decoration:none;color:inherit}
img{display:block}
ul{list-style:none}

/* ── LAYOUT ──────────────────────────────────────────────────────── */
.app-shell{display:flex;min-height:100vh;width:1440px;margin:0 auto}

/* Sidebar */
.sidebar{
  width:var(--sidebar-w);min-width:var(--sidebar-w);
  background:var(--color-sidebar-bg);display:flex;flex-direction:column;
  transition:width .25s ease,min-width .25s ease;
  position:sticky;top:0;height:100vh;overflow:hidden;z-index:100;
  flex-shrink:0}
.sidebar.collapsed{width:var(--sidebar-w-sm);min-width:var(--sidebar-w-sm)}
.sidebar-logo{display:flex;align-items:center;gap:var(--s2);
  padding:var(--s2) var(--s2);height:var(--topbar-h);border-bottom:1px solid rgba(255,255,255,.08)}
.sidebar-logo-icon{width:36px;height:36px;background:var(--color-primary-light);
  border-radius:var(--r-md);display:flex;align-items:center;justify-content:center;
  font-size:20px;flex-shrink:0}
.sidebar-logo-text{font-family:var(--font-display);font-size:var(--fz-md);
  font-weight:700;color:#fff;white-space:nowrap;line-height:1.2}
.sidebar-logo-sub{font-size:var(--text-caption);color:var(--color-sidebar-text);opacity:.7}
.sidebar-toggle{
  margin:var(--s2);background:var(--color-sidebar-hover);border:none;
  cursor:pointer;color:var(--color-sidebar-text);border-radius:var(--r-md);
  display:flex;align-items:center;justify-content:center;height:32px;
  transition:background .15s;flex-shrink:0}
.sidebar-toggle:hover{background:rgba(255,255,255,.12)}
.sidebar-nav{flex:1;overflow-y:auto;padding:var(--sp-2) 0}
.sidebar-section{padding:var(--s2) var(--s2) var(--sp-2);
  font-size:var(--text-caption);font-weight:700;letter-spacing:.08em;
  text-transform:uppercase;color:rgba(255,255,255,.35);white-space:nowrap;overflow:hidden}
.collapsed .sidebar-section{visibility:hidden;height:0;padding:0}
.nav-item{display:flex;align-items:center;gap:var(--s2);
  padding:var(--sp-3) var(--s2);color:var(--color-sidebar-text);
  cursor:pointer;border-radius:var(--r-md);margin:1px var(--sp-2);
  transition:background .15s;white-space:nowrap;position:relative;
  text-decoration:none;font-size:var(--fz-base)}
.nav-item:hover{background:var(--color-sidebar-hover)}
.nav-item.active{background:var(--color-sidebar-active);color:#fff}
.nav-item svg{flex-shrink:0}
.nav-label{white-space:nowrap;overflow:hidden;transition:opacity .2s}
.collapsed .nav-label{opacity:0;pointer-events:none}
.sidebar-footer{padding:var(--s2);border-top:1px solid rgba(255,255,255,.08)}

/* Main area */
.main{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}

/* Topbar */
.topbar{
  height:var(--topbar-h);background:var(--color-surface);
  border-bottom:1px solid var(--color-border);
  display:flex;align-items:center;gap:var(--s2);
  padding:0 var(--s4);position:sticky;top:0;z-index:50}
.topbar-logo{font-family:var(--font-display);font-size:var(--fz-xl);
  font-weight:700;color:var(--color-primary);margin-right:auto}
.topbar-search{display:flex;align-items:center;gap:var(--sp-2);
  background:var(--color-surface-alt);border:1px solid var(--color-border);
  border-radius:var(--r-full);padding:0 var(--s2);height:36px;
  font-size:var(--fz-base);color:var(--color-text-2);min-width:240px;cursor:pointer}
.topbar-icon-btn{width:40px;height:40px;display:flex;align-items:center;
  justify-content:center;border-radius:var(--r-full);cursor:pointer;
  color:var(--color-text-2);transition:background .15s;position:relative}
.topbar-icon-btn:hover{background:var(--color-surface-alt)}
.topbar-badge{position:absolute;top:6px;right:6px;width:8px;height:8px;
  background:var(--color-status-err);border-radius:50%;border:2px solid #fff}
.topbar-avatar{width:36px;height:36px;border-radius:50%;
  background:var(--color-primary-light);display:flex;align-items:center;
  justify-content:center;font-size:var(--fz-sm);font-weight:700;
  color:#fff;cursor:pointer;overflow:hidden}

/* Page content */
.page-content{flex:1;padding:var(--s4);overflow-y:auto}
.page-header{margin-bottom:var(--s4)}
.page-title{font-family:var(--font-display);font-size:var(--text-h2);
  font-weight:700;color:var(--color-text);line-height:1.2}
.page-subtitle{font-size:var(--text-body);color:var(--color-text-2);
  margin-top:var(--s1)}

/* ── ATOMS ───────────────────────────────────────────────────────── */

/* Image placeholder */
.img-box{background:var(--color-img-bg);border-radius:var(--card-img-radius);
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  color:var(--color-img-text);font-size:var(--fz-sm);font-family:var(--font-body);
  gap:var(--sp-2);border:1.5px dashed var(--prim-warm-300);position:relative;
  overflow:hidden;flex-shrink:0}
.img-box-emoji{font-size:28px;line-height:1}
.img-box-label{font-size:var(--fz-xs);opacity:.7;text-align:center;padding:0 8px}

/* Buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;
  gap:var(--sp-2);height:var(--btn-h);padding:0 var(--btn-px);
  border-radius:var(--btn-radius);font-family:var(--btn-font);
  font-size:var(--btn-fz);font-weight:var(--btn-fw);
  cursor:pointer;border:none;transition:all .15s;white-space:nowrap;
  text-decoration:none;line-height:1}
.btn-sm{height:var(--btn-h-sm);padding:0 var(--s2);font-size:var(--fz-sm)}
.btn-lg{height:var(--btn-h-lg);padding:0 var(--btn-px-lg);font-size:var(--fz-lg)}
.btn-full{width:100%}
.btn-primary{background:var(--color-primary);color:#fff}
.btn-primary:hover{background:var(--color-primary-dark)}
.btn-secondary{background:var(--color-surface-alt);color:var(--color-text);
  border:1px solid var(--color-border)}
.btn-secondary:hover{background:var(--prim-warm-200)}
.btn-outline{background:transparent;color:var(--color-primary);
  border:1.5px solid var(--color-primary)}
.btn-outline:hover{background:var(--color-primary-bg)}
.btn-ghost{background:transparent;color:var(--color-text-2)}
.btn-ghost:hover{background:var(--color-surface-alt)}
.btn-danger{background:var(--color-status-err);color:#fff}
.btn-danger:hover{background:#b91c1c}
.btn-link{background:transparent;color:var(--color-primary);
  height:auto;padding:0;font-weight:500}
.btn-link:hover{text-decoration:underline}

/* Inputs */
.input-wrap{display:flex;flex-direction:column;gap:var(--sp-2)}
.input-label{font-size:var(--fz-sm);font-weight:600;color:var(--color-text-2)}
.input{height:var(--input-h);background:var(--input-bg);border:1.5px solid var(--input-border);
  border-radius:var(--input-radius);padding:var(--input-px);
  font-size:var(--input-fz);font-family:var(--font-body);color:var(--color-text);
  width:100%;display:flex;align-items:center;gap:var(--sp-2)}
.input-lg{height:var(--input-h-lg)}
.input-hint{font-size:var(--fz-xs);color:var(--color-text-muted)}
.input-icon{color:var(--color-text-muted);display:flex;align-items:center}
.input-value{color:var(--color-text-muted);font-size:var(--fz-sm)}
.select-wrap{position:relative}
.select-arrow{position:absolute;right:12px;top:50%;transform:translateY(-50%);
  color:var(--color-text-muted);pointer-events:none}

/* Badges & chips */
.badge{display:inline-flex;align-items:center;gap:3px;
  padding:2px 8px;border-radius:var(--r-full);font-size:var(--fz-xs);font-weight:600}
.badge-green{background:var(--color-status-ok-bg);color:var(--color-status-ok)}
.badge-yellow{background:var(--color-status-warn-bg);color:var(--color-status-warn)}
.badge-red{background:var(--color-status-err-bg);color:var(--color-status-err)}
.badge-blue{background:var(--color-status-info-bg);color:var(--color-status-info)}
.badge-gray{background:var(--prim-gray-100);color:var(--prim-gray-600)}
.badge-primary{background:var(--color-primary-bg);color:var(--color-primary)}
.chip{display:inline-flex;align-items:center;gap:4px;
  padding:4px 12px;border-radius:var(--r-full);font-size:var(--fz-sm);
  background:var(--color-surface);border:1px solid var(--color-border);
  cursor:pointer;transition:all .15s;white-space:nowrap}
.chip:hover,.chip.active{background:var(--color-primary-bg);
  border-color:var(--color-primary);color:var(--color-primary)}

/* Card */
.card{background:var(--card-bg);border:1px solid var(--card-border);
  border-radius:var(--card-radius);box-shadow:var(--card-shadow);overflow:hidden}
.card-p{padding:var(--card-p)}
.card-p-sm{padding:var(--s2)}

/* Divider */
.divider{border:none;border-top:1px solid var(--color-border);margin:var(--s3) 0}
.divider-label{display:flex;align-items:center;gap:var(--s2);
  font-size:var(--fz-sm);color:var(--color-text-muted);margin:var(--s3) 0}
.divider-label::before,.divider-label::after{content:'';flex:1;
  border-top:1px solid var(--color-border)}

/* Stars */
.stars{display:inline-flex;align-items:center;gap:1px;color:#f59e0b}
.stars-count{font-size:var(--fz-sm);color:var(--color-text-2);margin-left:4px}

/* Counter stepper */
.counter{display:flex;align-items:center;border:1.5px solid var(--color-border);
  border-radius:var(--r-md);overflow:hidden;height:36px}
.counter-btn{width:36px;height:100%;display:flex;align-items:center;
  justify-content:center;background:var(--color-surface-alt);
  cursor:pointer;color:var(--color-text-2);flex-shrink:0}
.counter-btn:hover{background:var(--prim-warm-200)}
.counter-val{min-width:40px;text-align:center;font-size:var(--fz-base);
  font-weight:600;padding:0 var(--sp-2)}

/* Progress bar */
.progress-wrap{display:flex;flex-direction:column;gap:var(--sp-2)}
.progress-bar-bg{height:8px;background:var(--color-border);border-radius:var(--r-full);overflow:hidden}
.progress-bar-fill{height:100%;background:var(--color-primary);border-radius:var(--r-full);transition:width .3s}
.progress-meta{display:flex;justify-content:space-between;font-size:var(--fz-xs);
  color:var(--color-text-2)}

/* ── SECTION LAYOUT ──────────────────────────────────────────────── */
.section{margin-bottom:var(--s8)}
.section-hd{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:var(--s3)}
.section-title{font-family:var(--font-display);font-size:var(--text-h4);
  font-weight:700;color:var(--color-text)}
.section-subtitle{font-size:var(--fz-sm);color:var(--color-text-2);
  margin-top:2px}
.row{display:flex;gap:var(--s4)}
.col-2{display:grid;grid-template-columns:repeat(2,1fr);gap:var(--s4)}
.col-3{display:grid;grid-template-columns:repeat(3,1fr);gap:var(--s4)}
.col-4{display:grid;grid-template-columns:repeat(4,1fr);gap:var(--s4)}
.col-6{display:grid;grid-template-columns:repeat(6,1fr);gap:var(--s3)}
.flex-row{display:flex;align-items:center;gap:var(--s2)}
.flex-col{display:flex;flex-direction:column;gap:var(--s2)}
.ml-auto{margin-left:auto}
.mt-1{margin-top:var(--s1)} .mt-2{margin-top:var(--s2)}
.mt-3{margin-top:var(--s3)} .mt-4{margin-top:var(--s4)}
.mb-1{margin-bottom:var(--s1)} .mb-2{margin-bottom:var(--s2)}
.mb-3{margin-bottom:var(--s3)} .mb-4{margin-bottom:var(--s4)}
.gap-1{gap:var(--s1)} .gap-2{gap:var(--s2)}
.gap-3{gap:var(--s3)} .gap-4{gap:var(--s4)}
.text-sm{font-size:var(--fz-sm)} .text-xs{font-size:var(--fz-xs)}
.text-muted{color:var(--color-text-muted)}
.text-secondary{color:var(--color-text-2)}
.fw-600{font-weight:600} .fw-700{font-weight:700}
.font-display{font-family:var(--font-display)}

/* ── AUTH LAYOUT ─────────────────────────────────────────────────── */
.auth-shell{min-height:100vh;width:1440px;margin:0 auto;
  display:grid;grid-template-columns:1fr 1fr}
.auth-brand{background:var(--color-sidebar-bg);display:flex;flex-direction:column;
  align-items:center;justify-content:center;padding:var(--s8);gap:var(--s4)}
.auth-brand-logo{font-family:var(--font-display);font-size:var(--fz-7xl);
  font-weight:700;color:#fff;line-height:1}
.auth-brand-em{font-size:80px;line-height:1;margin-bottom:var(--s4)}
.auth-brand-tagline{font-size:var(--fz-xl);color:var(--color-sidebar-text);
  text-align:center;max-width:360px;line-height:1.6}
.auth-brand-tags{display:flex;gap:var(--s2);flex-wrap:wrap;justify-content:center;margin-top:var(--s4)}
.auth-brand-tag{background:rgba(255,255,255,.1);color:var(--color-sidebar-text);
  border-radius:var(--r-full);padding:4px 14px;font-size:var(--fz-sm)}
.auth-form-side{display:flex;flex-direction:column;align-items:center;
  justify-content:center;padding:var(--s8)}
.auth-form-box{width:100%;max-width:420px}
.auth-form-title{font-family:var(--font-display);font-size:var(--text-h2);
  font-weight:700;margin-bottom:var(--sp-2);color:var(--color-text)}
.auth-form-desc{font-size:var(--fz-base);color:var(--color-text-2);margin-bottom:var(--s4)}
.auth-form-fields{display:flex;flex-direction:column;gap:var(--s3)}
.auth-links{display:flex;justify-content:space-between;align-items:center;
  margin-top:var(--s3);font-size:var(--fz-sm)}

/* ── BANNER ──────────────────────────────────────────────────────── */
.banner{border-radius:var(--r-2xl);overflow:hidden;position:relative;
  min-height:280px;display:flex;align-items:flex-end;
  background:linear-gradient(135deg,var(--prim-green-800),var(--prim-green-600))}
.banner-img-placeholder{position:absolute;inset:0;background:var(--color-img-bg);
  display:flex;align-items:center;justify-content:center;font-size:64px;opacity:.35}
.banner-content{position:relative;z-index:1;padding:var(--s4);
  background:linear-gradient(to top,rgba(0,0,0,.6) 0%,transparent 100%);
  width:100%;color:#fff}
.banner-label{font-size:var(--fz-sm);background:var(--color-accent);
  color:#fff;padding:2px 10px;border-radius:var(--r-full);
  display:inline-block;margin-bottom:var(--sp-3)}
.banner-title{font-family:var(--font-display);font-size:var(--fz-4xl);
  font-weight:700;line-height:1.2;margin-bottom:var(--s2)}
.banner-dots{display:flex;gap:6px;margin-top:var(--s2)}
.banner-dot{width:8px;height:8px;border-radius:50%;
  background:rgba(255,255,255,.5)}
.banner-dot.active{background:#fff;width:24px}

/* ── CATEGORY GRID ───────────────────────────────────────────────── */
.cat-item{display:flex;flex-direction:column;align-items:center;gap:var(--sp-3);
  cursor:pointer;padding:var(--s2);border-radius:var(--r-lg);
  border:1.5px solid var(--color-border);background:var(--color-surface);
  transition:all .15s;text-align:center}
.cat-item:hover{border-color:var(--color-primary);
  background:var(--color-primary-bg)}
.cat-icon{width:56px;height:56px;border-radius:var(--r-lg);
  background:var(--color-surface-alt);display:flex;align-items:center;
  justify-content:center;font-size:28px}
.cat-name{font-size:var(--fz-sm);font-weight:600;color:var(--color-text)}

/* ── PRODUCT CARD ────────────────────────────────────────────────── */
.product-card{background:var(--color-surface);border:1px solid var(--color-border);
  border-radius:var(--card-radius);box-shadow:var(--sh-xs);
  overflow:hidden;transition:box-shadow .2s;cursor:pointer;
  display:flex;flex-direction:column;text-decoration:none;color:inherit}
.product-card:hover{box-shadow:var(--sh-md)}
.product-card-img{position:relative}
.product-card-fav{position:absolute;top:8px;right:8px;width:28px;height:28px;
  background:rgba(255,255,255,.85);border-radius:50%;display:flex;
  align-items:center;justify-content:center;color:var(--color-text-2);cursor:pointer}
.product-card-body{padding:var(--s2);flex:1;display:flex;flex-direction:column;gap:var(--sp-2)}
.product-card-name{font-size:var(--fz-base);font-weight:600;
  color:var(--color-text);line-height:1.3}
.product-card-farm{font-size:var(--fz-xs);color:var(--color-text-2);
  display:flex;align-items:center;gap:3px}
.product-card-meta{display:flex;align-items:center;gap:var(--sp-3);
  flex-wrap:wrap}
.product-card-price{font-size:var(--fz-lg);font-weight:700;color:var(--color-primary);
  margin-top:auto}
.product-card-unit{font-size:var(--fz-xs);color:var(--color-text-muted)}
.product-card-footer{padding:0 var(--s2) var(--s2)}

/* ── FARM CARD ───────────────────────────────────────────────────── */
.farm-card{background:var(--color-surface);border:1px solid var(--color-border);
  border-radius:var(--card-radius);box-shadow:var(--sh-xs);overflow:hidden;
  display:flex;flex-direction:column;cursor:pointer;text-decoration:none;color:inherit}
.farm-card:hover{box-shadow:var(--sh-md)}
.farm-card-body{padding:var(--s2);display:flex;flex-direction:column;gap:var(--sp-2);flex:1}
.farm-card-name{font-size:var(--fz-base);font-weight:700;color:var(--color-text)}
.farm-card-region{font-size:var(--fz-xs);color:var(--color-text-2)}
.farm-card-meta{display:flex;gap:var(--sp-2);flex-wrap:wrap}

/* ── MILES WIDGET ────────────────────────────────────────────────── */
.miles-widget{background:var(--color-primary);border-radius:var(--r-2xl);
  padding:var(--s4);color:#fff;display:flex;gap:var(--s4);align-items:center}
.miles-ring{width:80px;height:80px;border-radius:50%;border:3px solid rgba(255,255,255,.3);
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  flex-shrink:0;background:rgba(255,255,255,.1)}
.miles-ring-val{font-size:var(--fz-2xl);font-weight:700;line-height:1}
.miles-ring-unit{font-size:var(--fz-xs);opacity:.8}
.miles-info{flex:1}
.miles-title{font-family:var(--font-display);font-size:var(--fz-xl);font-weight:700;margin-bottom:var(--sp-2)}
.miles-desc{font-size:var(--fz-sm);opacity:.85;line-height:1.5}
.miles-tags{display:flex;gap:var(--sp-2);flex-wrap:wrap;margin-top:var(--s2)}
.miles-tag{background:rgba(255,255,255,.15);border-radius:var(--r-full);
  padding:3px 10px;font-size:var(--fz-xs)}

/* ── FILTER PANEL ────────────────────────────────────────────────── */
.filter-panel{background:var(--color-surface);border:1px solid var(--color-border);
  border-radius:var(--r-lg);padding:var(--s3)}
.filter-panel-title{font-size:var(--fz-sm);font-weight:700;
  color:var(--color-text);margin-bottom:var(--s2)}
.filter-chips{display:flex;flex-wrap:wrap;gap:var(--sp-2)}
.filter-range{display:flex;gap:var(--sp-2)}

/* ── MAP PLACEHOLDER ─────────────────────────────────────────────── */
.map-box{background:linear-gradient(145deg,#e0ead0,#c8d8a0);
  border-radius:var(--r-lg);position:relative;overflow:hidden;
  display:flex;align-items:center;justify-content:center}
.map-pin{position:absolute;font-size:24px;transform:translate(-50%,-100%)}
.map-overlay{position:absolute;bottom:0;left:0;right:0;
  background:linear-gradient(to top,rgba(255,255,255,.9),transparent);
  padding:var(--s3);display:flex;justify-content:flex-end}

/* ── ORDER ROW ───────────────────────────────────────────────────── */
.order-row{display:flex;align-items:center;gap:var(--s3);
  padding:var(--s3);border-bottom:1px solid var(--color-border);
  cursor:pointer;transition:background .15s}
.order-row:last-child{border-bottom:none}
.order-row:hover{background:var(--color-surface-alt)}
.order-row-num{font-size:var(--fz-sm);color:var(--color-text-muted);min-width:80px}
.order-row-info{flex:1}
.order-row-date{font-size:var(--fz-xs);color:var(--color-text-muted);margin-top:2px}
.order-row-total{font-size:var(--fz-base);font-weight:700;color:var(--color-text);
  min-width:100px;text-align:right}
.order-row-arrow{color:var(--color-text-muted)}

/* ── TOUR CARD ───────────────────────────────────────────────────── */
.tour-card{background:var(--color-surface);border:1px solid var(--color-border);
  border-radius:var(--card-radius);overflow:hidden;box-shadow:var(--sh-xs);
  cursor:pointer;text-decoration:none;color:inherit;display:block}
.tour-card:hover{box-shadow:var(--sh-md)}
.tour-card-body{padding:var(--s2)}
.tour-card-date{font-size:var(--fz-xs);color:var(--color-text-2);margin-bottom:2px}
.tour-card-name{font-size:var(--fz-base);font-weight:700;margin-bottom:var(--sp-2)}
.tour-card-farm{font-size:var(--fz-xs);color:var(--color-text-2)}
.tour-card-footer{display:flex;align-items:center;justify-content:space-between;
  padding:var(--s2);border-top:1px solid var(--color-border)}

/* ── GROUP CARD ──────────────────────────────────────────────────── */
.group-card{background:var(--color-surface);border:1.5px solid var(--color-border);
  border-radius:var(--card-radius);padding:var(--s3)}
.group-card-product{display:flex;gap:var(--s2);align-items:center;margin-bottom:var(--s2)}
.group-card-goal{font-size:var(--fz-sm);color:var(--color-text-2);margin-bottom:var(--sp-3)}

/* ── TIMELINE ────────────────────────────────────────────────────── */
.timeline{display:flex;flex-direction:column;gap:0}
.timeline-item{display:flex;gap:var(--s2);padding-bottom:var(--s3);position:relative}
.timeline-item:last-child{padding-bottom:0}
.timeline-item:not(:last-child)::before{
  content:'';position:absolute;left:15px;top:32px;bottom:0;
  width:2px;background:var(--color-border)}
.timeline-dot{width:32px;height:32px;border-radius:50%;flex-shrink:0;
  display:flex;align-items:center;justify-content:center;font-size:14px;
  border:2px solid var(--color-primary);background:var(--color-primary-bg)}
.timeline-dot.active{background:var(--color-primary);color:#fff}
.timeline-text{padding-top:4px}
.timeline-label{font-size:var(--fz-sm);font-weight:600}
.timeline-date{font-size:var(--fz-xs);color:var(--color-text-muted)}

/* ── CO2 STATS ───────────────────────────────────────────────────── */
.stat-card{background:var(--color-surface);border:1px solid var(--color-border);
  border-radius:var(--card-radius);padding:var(--s3);text-align:center}
.stat-card-icon{font-size:32px;margin-bottom:var(--sp-2)}
.stat-card-val{font-family:var(--font-display);font-size:var(--fz-5xl);
  font-weight:700;color:var(--color-primary);line-height:1}
.stat-card-unit{font-size:var(--fz-sm);color:var(--color-text-2);margin-top:2px}
.stat-card-label{font-size:var(--fz-xs);color:var(--color-text-muted);margin-top:var(--sp-2)}

/* ── ONBOARDING ──────────────────────────────────────────────────── */
.onboard-shell{min-height:100vh;width:1440px;margin:0 auto;
  display:flex;align-items:center;justify-content:center;
  background:var(--color-bg)}
.onboard-card{max-width:560px;width:100%;text-align:center;padding:var(--s8)}
.onboard-dots{display:flex;justify-content:center;gap:var(--sp-2);margin-top:var(--s4)}
.onboard-dot{width:10px;height:10px;border-radius:50%;background:var(--color-border)}
.onboard-dot.active{background:var(--color-primary);width:28px;border-radius:var(--r-full)}

/* ── COMBINED FILE ONLY ──────────────────────────────────────────── */
.combined-separator{background:var(--prim-gray-800);padding:var(--s4) var(--s4);
  display:flex;align-items:center;gap:var(--s3)}
.combined-screen-label{font-family:var(--font-body);font-size:var(--fz-sm);
  font-weight:700;color:var(--prim-gray-300);letter-spacing:.06em;text-transform:uppercase}
.combined-screen-id{font-size:var(--fz-xs);color:var(--prim-gray-500);margin-top:2px}

/* ── SCROLLBAR ───────────────────────────────────────────────────── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--color-border);border-radius:var(--r-full)}
`;

// ════════════════════════════════════════════════════════════════════
// SECTION 2 — FEATHER ICONS (inline SVG, 20×20)
// ════════════════════════════════════════════════════════════════════
const I = {
  home:    `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
  grid:    `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`,
  search:  `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  cart:    `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/></svg>`,
  map:     `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/></svg>`,
  users:   `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  user:    `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  heart:   `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
  settings:`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  pkg:     `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>`,
  pin:     `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>`,
  chart:   `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>`,
  bell:    `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
  menu:    `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>`,
  chevsL:  `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/></svg>`,
  chevsR:  `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 18 12 13 7"/><polyline points="6 17 11 12 6 7"/></svg>`,
  chevR:   `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>`,
  truck:   `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="3" width="15" height="13"/><polygon points="16 8 20 8 23 11 23 16 16 16 16 8"/><circle cx="5.5" cy="18.5" r="2.5"/><circle cx="18.5" cy="18.5" r="2.5"/></svg>`,
  leaf:    `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 22c1.25-.987 2.27-1.975 3.9-2.99C9.4 17 12 17 14.5 17c3 0 4.5 1 5.5 2.5 0 0 .5-5.5-2-9-2.5-3.5-5-4.5-8-4.5-3 0-5 2-6.5 4.5C2 13 2 17 2 22z"/><path d="M2 22c1.25-1.99 2.27-3.49 6-4.5"/></svg>`,
  plus16:  `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  minus16: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  x16:     `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  filter:  `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>`,
  star:    `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  check:   `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  logOut:  `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
  eye:     `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  refresh: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`,
  edit2:   `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>`,
  calendar:`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
  lock:    `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  mail:    `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>`,
  phone:   `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12 19.79 19.79 0 0 1 1.61 3.22a2 2 0 0 1 1.99-2.18h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.61a16 16 0 0 0 6 6l.92-.92a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>`,
  credit:  `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>`,
  shield:  `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  award:   `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>`,
};

// ════════════════════════════════════════════════════════════════════
// SECTION 3 — EMOJI MAP (тематические иконки)
// ════════════════════════════════════════════════════════════════════
const E = {
  carrot:'🥕', apple:'🍎', milk:'🥛', meat:'🥩', honey:'🍯',
  grain:'🌾', egg:'🥚', herb:'🌿', cheese:'🧀', berry:'🫐',
  mushroom:'🍄', potato:'🥔', tomato:'🍅', corn:'🌽', pumpkin:'🎃',
  fish:'🐟', farm:'🏡', tractor:'🚜', cow:'🐄', chicken:'🐓',
  earth:'🌍', leaf:'🍃', sun:'☀️', snow:'❄️', basket:'🧺',
  co2:'🌱', camera:'📸', shield:'🛡️', clock:'⏰', check:'✅',
  truck:'🚛', group:'👥', map:'🗺️', heart:'❤️', star:'⭐',
  gift:'🎁', calendar:'📅', tag:'🏷️', bag:'🛍️', seedling:'🌱',
  tree:'🌳', drop:'💧', fire:'🔥', tools:'🔧', certified:'🏅',
};

// ════════════════════════════════════════════════════════════════════
// SECTION 4 — ATOMIC COMPONENTS (render functions)
// ════════════════════════════════════════════════════════════════════

// Image placeholder box
function imgBox(w, h, emoji = '🖼️', label = '', style = '') {
  return `<div class="img-box" style="width:${w};height:${h};${style}">
    <div class="img-box-emoji">${emoji}</div>
    ${label ? `<div class="img-box-label">${label}</div>` : ''}
  </div>`;
}

// Button
function btn(label, { variant='primary', size='', href='#', full=false, icon='', emoji='' } = {}) {
  const cls = ['btn', `btn-${variant}`, size ? `btn-${size}` : '', full ? 'btn-full' : ''].filter(Boolean).join(' ');
  return `<a href="${href}" class="${cls}">${icon}${emoji ? emoji + ' ' : ''}${label}</a>`;
}

// Input field
function inputField(placeholder, { label='', type='text', icon='', value='', hint='' } = {}) {
  return `<div class="input-wrap">
    ${label ? `<div class="input-label">${label}</div>` : ''}
    <div class="input">
      ${icon ? `<span class="input-icon">${icon}</span>` : ''}
      <span class="input-value">${value || placeholder}</span>
    </div>
    ${hint ? `<div class="input-hint">${hint}</div>` : ''}
  </div>`;
}

// Select field
function selectField(placeholder, options = [], { label='', icon='' } = {}) {
  return `<div class="input-wrap">
    ${label ? `<div class="input-label">${label}</div>` : ''}
    <div class="select-wrap">
      <div class="input">
        ${icon ? `<span class="input-icon">${icon}</span>` : ''}
        <span class="input-value">${placeholder}</span>
      </div>
      <div class="select-arrow">▾</div>
    </div>
  </div>`;
}

// Badge
function badge(label, color = 'green') {
  return `<span class="badge badge-${color}">${label}</span>`;
}

// Chip filter
function chip(label, active = false) {
  return `<span class="chip${active ? ' active' : ''}">${label}</span>`;
}

// Stars rating
function stars(n = 4, count = '') {
  const s = Array(5).fill(0).map((_, i) =>
    `<span style="color:${i < n ? '#f59e0b' : '#d1d5db'}">${I.star}</span>`).join('');
  return `<span class="stars">${s}${count ? `<span class="stars-count">${count}</span>` : ''}</span>`;
}

// Counter stepper
function counter(val = 1) {
  return `<div class="counter">
    <div class="counter-btn">${I.minus16}</div>
    <div class="counter-val">${val}</div>
    <div class="counter-btn">${I.plus16}</div>
  </div>`;
}

// Progress bar
function progressBar(val = 60, label = '', meta = '') {
  return `<div class="progress-wrap">
    ${label ? `<div class="progress-meta"><span>${label}</span><span>${meta}</span></div>` : ''}
    <div class="progress-bar-bg"><div class="progress-bar-fill" style="width:${val}%"></div></div>
  </div>`;
}

// Section header
function sectionHd(title, subtitle = '', actionLabel = '', actionHref = '#') {
  return `<div class="section-hd">
    <div>
      <div class="section-title">${title}</div>
      ${subtitle ? `<div class="section-subtitle">${subtitle}</div>` : ''}
    </div>
    ${actionLabel ? `<a href="${actionHref}" class="btn btn-ghost btn-sm">${actionLabel} ${I.chevR}</a>` : ''}
  </div>`;
}

// Miles tag
function milesTag(km) {
  return `<span class="badge badge-green">${E.seedling} ${km} км</span>`;
}

// Cert badge
function certBadge(name) {
  return `<span class="badge badge-blue">${I.award} ${name}</span>`;
}

// Status badge
function statusBadge(status) {
  const map = {
    'Доставлен': 'green', 'В пути': 'blue', 'Обрабатывается': 'yellow',
    'Отменён': 'red', 'Активна': 'green', 'Приостановлена': 'yellow',
  };
  return badge(status, map[status] || 'gray');
}

// Divider with label
function divider(label = '') {
  if (!label) return `<hr class="divider">`;
  return `<div class="divider-label"><span>${label}</span></div>`;
}

// Info row (label + value)
function infoRow(label, value) {
  return `<div style="display:flex;align-items:flex-start;gap:16px;padding:10px 0;border-bottom:1px solid var(--color-border)">
    <div style="min-width:160px;font-size:13px;color:var(--color-text-2)">${label}</div>
    <div style="font-size:14px;font-weight:500">${value}</div>
  </div>`;
}

// ════════════════════════════════════════════════════════════════════
// SECTION 5 — MOLECULES
// ════════════════════════════════════════════════════════════════════

// Product card
function productCard({ name, price, unit='/кг', farm, emoji='🥦', miles=42, href='product.html', rating=4 }) {
  return `<a href="${href}" class="product-card">
    <div class="product-card-img">
      ${imgBox('100%','160px', emoji, name)}
      <div class="product-card-fav">${I.heart}</div>
    </div>
    <div class="product-card-body">
      <div class="product-card-name">${name}</div>
      <div class="product-card-meta">
        ${milesTag(miles)}
        ${stars(rating, `(${Math.floor(Math.random()*50)+8})`)}
      </div>
      <div class="product-card-farm">${I.home} ${farm}</div>
      <div class="product-card-price">${price} ₽<span class="product-card-unit">${unit}</span></div>
    </div>
    <div class="product-card-footer">
      ${btn('В корзину', { variant:'primary', size:'sm', full:true, href:'cart.html', icon: I.cart })}
    </div>
  </a>`;
}

// Farmer card
function farmerCard({ name, region, desc, emoji='🚜', rating=4, miles=35, products=24, href='farmer.html' }) {
  return `<a href="${href}" class="farm-card">
    ${imgBox('100%','140px', emoji, `${name} — ${region}`)}
    <div class="farm-card-body">
      <div class="farm-card-name">${name}</div>
      <div class="farm-card-region">${E.pin || '📍'} ${region}</div>
      <div class="farm-card-meta">
        ${milesTag(miles)}
        ${badge(`${products} товаров`, 'gray')}
      </div>
      ${stars(rating)}
    </div>
  </a>`;
}

// Tour card
function tourCard({ name, date, price, farm, emoji='🌾', seats=12, href='tour-detail.html' }) {
  return `<a href="${href}" class="tour-card">
    ${imgBox('100%','160px', emoji, name)}
    <div class="tour-card-body">
      <div class="tour-card-date">${I.calendar} ${date}</div>
      <div class="tour-card-name">${name}</div>
      <div class="tour-card-farm">${E.tractor} ${farm}</div>
    </div>
    <div class="tour-card-footer">
      <strong style="color:var(--color-primary)">${price} ₽/чел</strong>
      ${badge(`${seats} мест`, 'green')}
    </div>
  </a>`;
}

// Group buy card
function groupCard({ name, emoji='🧺', current=8, target=15, discount=12, href='group-buys.html' }) {
  const pct = Math.round(current/target*100);
  return `<div class="group-card">
    <div class="group-card-product">
      ${imgBox('56px','56px', emoji, '')}
      <div>
        <div style="font-weight:700">${name}</div>
        <div class="group-card-goal">Участников: ${current} из ${target}</div>
        ${badge(`-${discount}%`, 'green')}
      </div>
    </div>
    ${progressBar(pct, `${current}/${target} участников`, `−${discount}%`)}
    <div style="margin-top:16px">
      ${btn('Вступить в группу', { variant:'primary', size:'sm', full:true, href, emoji: E.group })}
    </div>
  </div>`;
}

// Subscription basket card
function basketCard({ name, items, price, emoji='🧺', href='subscriptions.html' }) {
  return `<div class="card card-p" style="border:1.5px solid var(--color-border)">
    <div style="display:flex;gap:16px;align-items:flex-start">
      ${imgBox('72px','72px', emoji, '')}
      <div style="flex:1">
        <div style="font-weight:700;font-size:15px">${name}</div>
        <div style="font-size:12px;color:var(--color-text-2);margin:4px 0">${items}</div>
        <div style="font-size:18px;font-weight:700;color:var(--color-primary)">${price} ₽</div>
      </div>
    </div>
    <div style="margin-top:16px;display:flex;gap:8px">
      ${btn('Оформить подписку', { variant:'primary', size:'sm', href })}
      ${btn('Настроить состав', { variant:'secondary', size:'sm', href })}
    </div>
  </div>`;
}

// Order row
function orderRow({ id, date, status, total, href='order-detail.html', items=3 }) {
  return `<a href="${href}" class="order-row" style="text-decoration:none">
    <div class="order-row-num">#${id}</div>
    <div class="order-row-info">
      <div style="font-weight:600">${items} позиц.</div>
      <div class="order-row-date">${date}</div>
    </div>
    <div>${statusBadge(status)}</div>
    <div class="order-row-total">${total} ₽</div>
    <div class="order-row-arrow">${I.chevR}</div>
  </a>`;
}

// Cart item row
function cartItem({ name, farm, price, emoji='🥦', qty=2 }) {
  return `<div style="display:flex;gap:16px;align-items:center;padding:16px 0;border-bottom:1px solid var(--color-border)">
    ${imgBox('64px','64px', emoji, '')}
    <div style="flex:1">
      <div style="font-weight:600">${name}</div>
      <div style="font-size:12px;color:var(--color-text-2);margin-top:2px">${E.tractor} ${farm}</div>
    </div>
    ${counter(qty)}
    <div style="min-width:100px;text-align:right;font-weight:700;font-size:16px">${price * qty} ₽</div>
    <button style="background:none;border:none;cursor:pointer;color:var(--color-text-muted);padding:8px">${I.x16}</button>
  </div>`;
}

// Nav item for sidebar
function navItem(icon, label, href, active = false) {
  return `<a href="${href}" class="nav-item${active ? ' active' : ''}">
    ${icon}<span class="nav-label">${label}</span>
  </a>`;
}

// ════════════════════════════════════════════════════════════════════
// SECTION 6 — LAYOUT TEMPLATES
// ════════════════════════════════════════════════════════════════════

const NAV_ITEMS = [
  { icon: I.home,    label: 'Главная',          href: 'home.html',       id: 'home' },
  { icon: I.grid,    label: 'Каталог',           href: 'catalog.html',    id: 'catalog' },
  { icon: I.search,  label: 'Поиск и фильтры',  href: 'search.html',     id: 'search' },
  { icon: I.map,     label: 'Карта ферм',        href: 'farm-map.html',   id: 'farm-map' },
  { icon: I.cart,    label: 'Корзина',           href: 'cart.html',       id: 'cart' },
  { icon: I.pkg,     label: 'Мои заказы',        href: 'orders.html',     id: 'orders' },
  { icon: I.users,   label: 'Групповые закупки', href: 'group-buys.html', id: 'group-buys' },
  { icon: I.truck,   label: 'Экскурсии',         href: 'tours.html',      id: 'tours' },
  { icon: I.heart,   label: 'Избранное',         href: 'favorites.html',  id: 'favorites' },
  { icon: I.leaf,    label: 'Подписки',          href: 'subscriptions.html', id: 'subscriptions' },
];
const NAV_PROFILE = [
  { icon: I.user,    label: 'Профиль',           href: 'profile.html',    id: 'profile' },
  { icon: I.pin,     label: 'Адреса доставки',   href: 'addresses.html',  id: 'addresses' },
  { icon: I.chart,   label: 'CO₂ статистика',    href: 'co2.html',        id: 'co2' },
  { icon: I.settings,label: 'Настройки',          href: 'settings.html',   id: 'settings' },
];

function sidebarHTML(active) {
  const shopItems = NAV_ITEMS.map(n =>
    navItem(n.icon, n.label, n.href, n.id === active)).join('');
  const profileItems = NAV_PROFILE.map(n =>
    navItem(n.icon, n.label, n.href, n.id === active)).join('');

  return `
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon">🌿</div>
      <div class="nav-label">
        <div class="sidebar-logo-text">Местные</div>
        <div class="sidebar-logo-sub">Продукты</div>
      </div>
    </div>
    <button class="sidebar-toggle" onclick="toggleSidebar()" title="Свернуть меню">
      <span id="sidebar-toggle-icon">${I.chevsL}</span>
    </button>
    <nav class="sidebar-nav">
      <div class="sidebar-section">Магазин</div>
      ${shopItems}
      <div class="sidebar-section" style="margin-top:16px">Аккаунт</div>
      ${profileItems}
    </nav>
    <div class="sidebar-footer">
      <a href="login.html" class="nav-item" style="color:var(--color-status-err)">
        ${I.logOut}<span class="nav-label">Выйти</span>
      </a>
    </div>
  </aside>`;
}

function topbarHTML({ title = '', showSearch = true, showCart = true, showAvatar = true } = {}) {
  return `
  <header class="topbar">
    ${title ? `<div class="topbar-logo">${title}</div>` : `<div class="topbar-logo">🌿 Местные Продукты</div>`}
    ${showSearch ? `
    <a href="search.html" class="topbar-search" style="flex:1;max-width:400px;margin:0 auto">
      ${I.search}
      <span>Поиск товаров, ферм…</span>
    </a>` : ''}
    <div style="display:flex;align-items:center;gap:4px;margin-left:auto">
      <div class="topbar-icon-btn">${I.bell}<span class="topbar-badge"></span></div>
      ${showCart ? `<a href="cart.html" class="topbar-icon-btn">${I.cart}</a>` : ''}
      ${showAvatar ? `<a href="profile.html" class="topbar-avatar">АС</a>` : ''}
    </div>
  </header>`;
}

// Full app shell wrapper
function appShell({ active, pageTitle = '', content = '', showSearch = true }) {
  return `
  <div class="app-shell">
    ${sidebarHTML(active)}
    <div class="main">
      ${topbarHTML({ title: pageTitle, showSearch })}
      <div class="page-content">
        ${content}
      </div>
    </div>
  </div>
  <script>
    function toggleSidebar() {
      const s = document.getElementById('sidebar');
      const ic = document.getElementById('sidebar-toggle-icon');
      s.classList.toggle('collapsed');
      ic.innerHTML = s.classList.contains('collapsed')
        ? '${I.chevsR.replace(/`/g,"'")}'
        : '${I.chevsL.replace(/`/g,"'")}';
    }
  </script>`;
}

// Auth shell wrapper (no sidebar)
function authShell(content) {
  return `
  <div class="auth-shell">
    <div class="auth-brand">
      <div class="auth-brand-em">🌿</div>
      <div class="auth-brand-logo">Местные<br>Продукты</div>
      <div class="auth-brand-tagline">Свежие продукты прямо с местных ферм — с заботой о природе и здоровье</div>
      <div class="auth-brand-tags">
        <span class="auth-brand-tag">${E.carrot} Натуральное</span>
        <span class="auth-brand-tag">${E.tractor} Местные фермеры</span>
        <span class="auth-brand-tag">${E.co2} Экологично</span>
        <span class="auth-brand-tag">${E.truck} Быстрая доставка</span>
      </div>
    </div>
    <div class="auth-form-side">${content}</div>
  </div>`;
}

// Bare shell (onboarding / payment success)
function bareShell(content) {
  return `<div class="onboard-shell">${content}</div>`;
}

// ════════════════════════════════════════════════════════════════════
// SECTION 7 — PAGE GENERATORS
// ════════════════════════════════════════════════════════════════════

// ── S01: Login ────────────────────────────────────────────────────
function pageLogin() {
  return authShell(`
  <div class="auth-form-box">
    <div class="auth-form-title">Добро пожаловать</div>
    <div class="auth-form-desc">Войдите, чтобы покупать свежие продукты у местных фермеров</div>
    <div class="auth-form-fields">
      ${inputField('anna@example.com', { label:'Email или телефон', icon: I.mail })}
      ${inputField('••••••••', { label:'Пароль', type:'password', icon: I.lock })}
    </div>
    <div class="auth-links">
      <a href="recovery.html" style="color:var(--color-primary);font-size:13px">Забыли пароль?</a>
      ${badge('Роль: Покупатель', 'primary')}
    </div>
    <div style="margin-top:24px;display:flex;flex-direction:column;gap:12px">
      ${btn('Войти', { variant:'primary', size:'lg', full:true, href:'onboarding.html' })}
      ${divider('или')}
      ${btn('Зарегистрироваться', { variant:'secondary', size:'lg', full:true, href:'register.html' })}
    </div>
  </div>`);
}

// ── S02: Register ─────────────────────────────────────────────────
function pageRegister() {
  return authShell(`
  <div class="auth-form-box">
    <div class="auth-form-title">Создать аккаунт</div>
    <div class="auth-form-desc">Присоединяйтесь к сообществу любителей местных продуктов</div>
    <div class="auth-form-fields">
      ${inputField('Анна Смирнова', { label:'Имя и фамилия', icon: I.user })}
      ${inputField('anna@example.com', { label:'Email', icon: I.mail })}
      ${inputField('+7 (900) 123-45-67', { label:'Телефон', icon: I.phone })}
      ${inputField('••••••••', { label:'Пароль', icon: I.lock })}
      ${inputField('••••••••', { label:'Повторите пароль', icon: I.lock })}
      ${selectField('Покупатель', ['Покупатель','Фермер'], { label:'Я регистрируюсь как', icon: I.users })}
    </div>
    <div style="margin-top:24px;display:flex;flex-direction:column;gap:12px">
      ${btn('Создать аккаунт', { variant:'primary', size:'lg', full:true, href:'login.html' })}
      ${btn('Уже есть аккаунт — Войти', { variant:'ghost', size:'lg', full:true, href:'login.html' })}
    </div>
  </div>`);
}

// ── S03: Password Recovery ────────────────────────────────────────
function pageRecovery() {
  return authShell(`
  <div class="auth-form-box">
    <div class="auth-form-title">Восстановление пароля</div>
    <div class="auth-form-desc">Введите email — пришлём ссылку для сброса</div>
    <div class="auth-form-fields">
      ${inputField('anna@example.com', { label:'Email или логин', icon: I.mail })}
    </div>
    <div style="margin-top:24px;display:flex;flex-direction:column;gap:12px">
      ${btn('Отправить код', { variant:'primary', size:'lg', full:true, href:'confirm-code.html' })}
      ${btn('Вернуться к входу', { variant:'ghost', size:'lg', full:true, href:'login.html' })}
    </div>
  </div>`);
}

// ── S04: Confirm Code ─────────────────────────────────────────────
function pageConfirmCode() {
  return authShell(`
  <div class="auth-form-box">
    <div class="auth-form-title">Введите код</div>
    <div class="auth-form-desc">Мы отправили 6-значный код на anna@example.com</div>
    <div class="auth-form-fields">
      ${inputField('_ _ _ _ _ _', { label:'Код из письма', icon: I.shield })}
    </div>
    <div style="margin-top:8px;font-size:13px;color:var(--color-text-2)">
      Не пришло письмо? <a href="recovery.html" style="color:var(--color-primary)">Отправить ещё раз</a>
    </div>
    <div style="margin-top:24px">
      ${btn('Подтвердить', { variant:'primary', size:'lg', full:true, href:'new-password.html' })}
    </div>
  </div>`);
}

// ── S05: New Password ─────────────────────────────────────────────
function pageNewPassword() {
  return authShell(`
  <div class="auth-form-box">
    <div class="auth-form-title">Новый пароль</div>
    <div class="auth-form-desc">Придумайте надёжный пароль для вашего аккаунта</div>
    <div class="auth-form-fields">
      ${inputField('••••••••', { label:'Новый пароль', icon: I.lock })}
      ${inputField('••••••••', { label:'Повторите новый пароль', icon: I.lock })}
    </div>
    <div style="margin-top:24px">
      ${btn('Сохранить пароль', { variant:'primary', size:'lg', full:true, href:'login.html' })}
    </div>
  </div>`);
}

// ── S06: Onboarding ───────────────────────────────────────────────
function pageOnboarding() {
  const slides = [
    { emoji:'🌿', title:'Продукты с душой', desc:'Свежие овощи, молоко, мясо и мёд — прямо от фермеров вашего региона без посредников.' },
    { emoji:'🗺️', title:'Пищевые мили', desc:'Видите, сколько километров проехал каждый продукт. Меньше пути — свежее и экологичнее.' },
    { emoji:'🧺', title:'Сезонные корзины', desc:'Подписка на еженедельную корзину — фермер сам кладёт лучшее, что уродилось сегодня.' },
  ];
  const slide = slides[0];
  return bareShell(`
  <div class="onboard-card">
    <div style="font-size:80px;line-height:1;margin-bottom:32px">${slide.emoji}</div>
    <h1 style="font-family:var(--font-display);font-size:var(--fz-4xl);font-weight:700;margin-bottom:16px">${slide.title}</h1>
    <p style="font-size:var(--fz-lg);color:var(--color-text-2);line-height:1.7;max-width:400px;margin:0 auto">${slide.desc}</p>
    <div class="onboard-dots">
      <div class="onboard-dot active"></div>
      <div class="onboard-dot"></div>
      <div class="onboard-dot"></div>
    </div>
    <div style="margin-top:40px;display:flex;gap:16px;justify-content:center">
      ${btn('Далее', { variant:'primary', size:'lg', href:'home.html' })}
      ${btn('Пропустить', { variant:'ghost', size:'lg', href:'home.html' })}
    </div>
  </div>`);
}

// ── S07: Home ─────────────────────────────────────────────────────
function pageHome() {
  const cats = [
    { emoji: E.carrot,   name: 'Овощи' },
    { emoji: E.apple,    name: 'Фрукты' },
    { emoji: E.milk,     name: 'Молочное' },
    { emoji: E.meat,     name: 'Мясо' },
    { emoji: E.honey,    name: 'Мёд' },
    { emoji: E.grain,    name: 'Зерновые' },
    { emoji: E.egg,      name: 'Яйца' },
    { emoji: E.herb,     name: 'Зелень' },
    { emoji: E.berry,    name: 'Ягоды' },
    { emoji: E.mushroom, name: 'Грибы' },
    { emoji: E.cheese,   name: 'Сыр' },
    { emoji: E.fish,     name: 'Рыба' },
  ];
  const catGrid = cats.map(c => `
    <a href="catalog.html" class="cat-item">
      <div class="cat-icon">${c.emoji}</div>
      <div class="cat-name">${c.name}</div>
    </a>`).join('');

  const products = [
    { name:'Томаты черри', price:280, emoji:E.tomato, farm:'КФХ Петровых', miles:18 },
    { name:'Молоко 3.5%',  price:120, emoji:E.milk,   farm:'Ферма Зорька',  miles:34 },
    { name:'Мёд гречишный',price:650, emoji:E.honey,  farm:'Пасека Лесная', miles:56 },
    { name:'Яйца С0',      price:190, emoji:E.egg,    farm:'Птицеферма Нива',miles:22 },
  ];

  const farms = [
    { name:'КФХ Петровых',   region:'Тульская обл., 18 км', emoji:E.tractor, rating:5, miles:18, products:32 },
    { name:'Ферма Зорька',   region:'Калужская обл., 34 км', emoji:E.cow,    rating:4, miles:34, products:18 },
    { name:'Пасека Лесная',  region:'Рязанская обл., 56 км', emoji:E.honey,  rating:5, miles:56, products:7  },
  ];

  const tours = [
    { name:'День на молочной ферме', date:'24 мая', price:800,  farm:'Ферма Зорька',  emoji:E.cow,    seats:8  },
    { name:'Сбор клубники',          date:'1 июня', price:600,  farm:'КФХ Петровых',  emoji:E.berry,  seats:15 },
    { name:'Пасека: мёд своими руками',date:'8 июня',price:1200,farm:'Пасека Лесная', emoji:E.honey,  seats:6  },
  ];

  const groups = [
    { name:'Картофель молодой 10 кг', emoji:E.potato,  current:11, target:20, discount:15 },
    { name:'Корзина овощей «Лето»',   emoji:E.basket,  current:7,  target:15, discount:20 },
  ];

  return appShell({ active:'home', content:`
  <!-- BANNER -->
  <section class="section">
    <div class="banner">
      <div class="banner-img-placeholder">${E.sun}</div>
      <div class="banner-content">
        <div class="banner-label">🌱 Сезон открыт</div>
        <div class="banner-title">Первая клубника<br>уже у фермеров</div>
        ${btn('Смотреть акции', { variant:'outline', href:'catalog.html', emoji:E.berry })}
        <div class="banner-dots">
          <div class="banner-dot active"></div>
          <div class="banner-dot"></div>
          <div class="banner-dot"></div>
        </div>
      </div>
    </div>
  </section>

  <!-- CATEGORIES -->
  <section class="section">
    ${sectionHd('Категории товаров','', 'Все категории', 'catalog.html')}
    <div class="col-6">${catGrid}</div>
  </section>

  <!-- FOOD MILES WIDGET -->
  <section class="section">
    ${sectionHd('Пищевые мили', 'Ваш вклад в экологию')}
    <div class="miles-widget">
      <div class="miles-ring">
        <div class="miles-ring-val">42</div>
        <div class="miles-ring-unit">км</div>
      </div>
      <div class="miles-info">
        <div class="miles-title">Средняя дистанция от фермы до вас</div>
        <div class="miles-desc">Продукты из вашей последней корзины проехали суммарно 168 км — это на 74% меньше, чем в среднем по супермаркетам.</div>
        <div class="miles-tags">
          <span class="miles-tag">${E.co2} −2.3 кг CO₂</span>
          <span class="miles-tag">${E.leaf} 8 локальных ферм</span>
          <span class="miles-tag">${E.check} Верификация фермеров</span>
        </div>
      </div>
      ${btn('Настроить радиус', { variant:'outline', href:'search.html', emoji:'🎯' })}
    </div>
  </section>

  <!-- POPULAR PRODUCTS -->
  <section class="section">
    ${sectionHd('Популярные товары', 'Чаще всего заказывают', 'Все товары', 'catalog.html')}
    <div class="col-4">
      ${products.map(p => productCard({ ...p, href:'product.html' })).join('')}
    </div>
  </section>

  <!-- SEASONAL BASKETS -->
  <section class="section">
    ${sectionHd('Сезонные корзины', 'Подписка с еженедельной доставкой', 'Все корзины', 'subscriptions.html')}
    <div class="col-2">
      ${basketCard({ name:'Весенняя корзина', items:'Редис, зелень, шпинат, укроп, петрушка, салат', price:890,  emoji:E.basket })}
      ${basketCard({ name:'Молочная корзина', items:'Молоко, кефир, творог, сметана, масло',         price:1240, emoji:E.milk   })}
    </div>
  </section>

  <!-- NEAR FARMS -->
  <section class="section">
    ${sectionHd('Фермеры поблизости', 'В радиусе 60 км от вас', 'Карта ферм', 'farm-map.html')}
    <div class="col-3">
      ${farms.map(f => farmerCard({ ...f, href:'farmer.html' })).join('')}
    </div>
  </section>

  <!-- TOURS -->
  <section class="section">
    ${sectionHd('Ближайшие экскурсии', 'Побывайте на живой ферме', 'Все экскурсии', 'tours.html')}
    <div class="col-3">
      ${tours.map(t => tourCard({ ...t, href:'tour-detail.html' })).join('')}
    </div>
  </section>

  <!-- GROUP BUYS -->
  <section class="section">
    ${sectionHd('Групповые закупки', 'Покупайте вместе — платите меньше', 'Все группы', 'group-buys.html')}
    <div class="col-2">
      ${groups.map(g => groupCard({ ...g, href:'group-buys.html' })).join('')}
    </div>
  </section>
  `});
}

// ── S08: Catalog ──────────────────────────────────────────────────
function pageCatalog() {
  const items = [
    { name:'Томаты черри',      price:280, emoji:E.tomato,   farm:'КФХ Петровых',   miles:18, rating:5 },
    { name:'Молоко 3.5%',       price:120, emoji:E.milk,     farm:'Ферма Зорька',   miles:34, rating:4 },
    { name:'Мёд гречишный',     price:650, emoji:E.honey,    farm:'Пасека Лесная',  miles:56, rating:5 },
    { name:'Яйца С0',           price:190, emoji:E.egg,      farm:'Птицеферма Нива',miles:22, rating:4 },
    { name:'Сыр козий',         price:520, emoji:E.cheese,   farm:'КФХ Петровых',   miles:18, rating:5 },
    { name:'Клубника свежая',   price:380, emoji:E.berry,    farm:'КФХ Солнечное',  miles:29, rating:4 },
    { name:'Картофель молодой', price:95,  emoji:E.potato,   farm:'Агро Нива',      miles:41, rating:4 },
    { name:'Зелень ассорти',    price:140, emoji:E.herb,     farm:'КФХ Петровых',   miles:18, rating:5 },
  ];

  return appShell({ active:'catalog', content:`
  <div class="page-header">
    <div class="page-title">Каталог товаров</div>
    <div class="page-subtitle">Найдено 247 позиций от 38 фермеров</div>
  </div>

  <!-- Filters row -->
  <div style="display:flex;gap:16px;align-items:center;margin-bottom:32px;flex-wrap:wrap">
    <div class="input" style="flex:1;max-width:360px;cursor:pointer">
      ${I.search}<span class="input-value">Поиск в каталоге…</span>
    </div>
    ${btn('Фильтры', { variant:'secondary', icon: I.filter })}
    <div class="filter-chips">
      ${chip('Все',        true)}
      ${chip('Овощи')}
      ${chip('Молочное')}
      ${chip('Мясо')}
      ${chip('Мёд')}
      ${chip('Ягоды')}
    </div>
    <div style="margin-left:auto">
      ${selectField('По популярности', ['По популярности','По цене ↑','По цене ↓','Ближе всего'], { icon: I.filter })}
    </div>
  </div>

  <!-- Grid -->
  <div class="col-4">
    ${items.map(p => productCard({ ...p, href:'product.html' })).join('')}
  </div>
  <div style="display:flex;justify-content:center;margin-top:40px">
    ${btn('Загрузить ещё', { variant:'secondary', size:'lg' })}
  </div>
  `});
}

// ── S09: Product Detail ───────────────────────────────────────────
function pageProduct() {
  return appShell({ active:'catalog', content:`
  <div style="display:flex;gap:48px;align-items:flex-start">

    <!-- Left: images -->
    <div style="flex:0 0 480px">
      ${imgBox('480px','380px', E.tomato, 'Томаты черри')}
      <div style="display:flex;gap:8px;margin-top:12px">
        ${imgBox('88px','68px', E.tomato, '')}
        ${imgBox('88px','68px', E.tomato, '')}
        ${imgBox('88px','68px', E.tomato, '')}
        ${imgBox('88px','68px', E.tomato, '')}
      </div>
    </div>

    <!-- Right: info -->
    <div style="flex:1">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:8px">
        <h1 style="font-family:var(--font-display);font-size:var(--fz-4xl);font-weight:700;line-height:1.2">Томаты черри «Белла Роза»</h1>
        <button style="background:none;border:none;cursor:pointer;color:var(--color-text-muted);padding:4px">${I.heart}</button>
      </div>

      <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px">
        ${stars(5, '(42 отзыва)')}
        ${milesTag(18)}
        ${badge('Органик', 'green')}
        ${certBadge('ГОСТ Р')}
      </div>

      <a href="farmer.html" style="display:inline-flex;align-items:center;gap:8px;color:var(--color-primary);font-weight:600;margin-bottom:24px">
        ${E.tractor} КФХ Петровых — Тульская обл.
        ${I.chevR}
      </a>

      <div style="font-size:14px;color:var(--color-text-2);line-height:1.7;margin-bottom:24px">
        Черри-томаты сорта «Белла Роза» выращены в открытом грунте без применения пестицидов. Тонкая кожица, насыщенный сладкий вкус. Идеальны для салатов, закусок и запекания. Сбор — ежедневно утром, доставка в день сбора.
      </div>

      <div style="margin-bottom:32px">
        ${infoRow('Вес/упаковка', '500 г')}
        ${infoRow('Пищевые мили', `${E.seedling} 18 км от фермы`)}
        ${infoRow('Хранение', '5–7 дней при +4°C')}
        ${infoRow('Сертификаты', `${certBadge('ГОСТ Р')} ${certBadge('ЭКО')}`)}
        ${infoRow('Производитель', 'ИП Петров С.А., Тула')}
      </div>

      <!-- Price + add to cart -->
      <div style="display:flex;align-items:center;gap:24px;padding:24px;background:var(--color-surface-alt);border-radius:var(--r-lg);margin-bottom:24px">
        <div>
          <div style="font-size:32px;font-weight:700;color:var(--color-primary)">280 ₽</div>
          <div style="font-size:12px;color:var(--color-text-muted)">за 500 г</div>
        </div>
        ${counter(1)}
        ${btn('В корзину', { variant:'primary', size:'lg', href:'cart.html', icon: I.cart })}
        ${btn('В избранное', { variant:'outline', href:'favorites.html', icon: I.heart })}
      </div>

      ${btn('Подписаться на уведомления о наличии', { variant:'ghost', icon: I.bell })}
    </div>
  </div>

  <!-- Reviews section -->
  <div class="section" style="margin-top:64px">
    ${sectionHd('Отзывы покупателей', '42 отзыва')}
    ${[
      { author:'Анна С.', text:'Заказываю уже третий раз! Томаты всегда свежие, кожица тонкая, не лопается. Дети едят как конфеты.', rating:5, date:'12 мая 2025' },
      { author:'Дмитрий К.', text:'Отличное соотношение цена/качество. Видно, что выращено с любовью, а не в теплице на гидропонике.', rating:5, date:'8 мая 2025' },
    ].map(r => `
      <div class="card card-p" style="margin-bottom:16px">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
          <div class="topbar-avatar">${r.author[0]}</div>
          <div><div style="font-weight:600">${r.author}</div><div style="font-size:12px;color:var(--color-text-muted)">${r.date}</div></div>
          <div style="margin-left:auto">${stars(r.rating)}</div>
        </div>
        <div style="font-size:14px;color:var(--color-text-2);line-height:1.6">${r.text}</div>
      </div>`).join('')}
  </div>
  `});
}

// ── S10: Farmer Profile ───────────────────────────────────────────
function pageFarmer() {
  return appShell({ active:'catalog', content:`
  <!-- Cover -->
  ${imgBox('100%','280px', E.farm, 'КФХ Петровых — Тульская область', 'border-radius:var(--r-2xl)')}

  <!-- Info row -->
  <div style="display:flex;gap:32px;align-items:flex-start;margin-top:32px;margin-bottom:40px">
    <div style="flex:0 0 200px;text-align:center">
      ${imgBox('120px','120px', E.tractor, '', 'border-radius:50%;margin:0 auto')}
      <div style="font-size:11px;color:var(--color-text-muted);margin-top:8px">Сергей Петров</div>
    </div>
    <div style="flex:1">
      <h1 style="font-family:var(--font-display);font-size:var(--fz-4xl);font-weight:700;margin-bottom:8px">КФХ Петровых</h1>
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:16px">
        ${badge('📍 Тульская обл., 18 км', 'gray')}
        ${stars(5, '(128 отзывов)')}
        ${badge('На платформе с 2022', 'primary')}
        ${certBadge('ГОСТ Р')} ${certBadge('ЭКО')} ${certBadge('БИО')}
      </div>
      <p style="font-size:14px;color:var(--color-text-2);line-height:1.7;max-width:640px">
        Семейное хозяйство в Тульской области. Выращиваем овощи и зелень в открытом грунте с 1998 года.
        Никакой химии — только природные удобрения и любовь к земле. Ежедневный сбор и доставка в день сбора.
      </p>
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:24px">
        ${btn('Подписаться на фермера', { variant:'primary', icon: I.bell })}
        ${btn('Показать на карте', { variant:'secondary', href:'farm-map.html', icon: I.map })}
        ${btn('Написать фермеру', { variant:'outline' })}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;flex:0 0 260px">
      <div class="stat-card"><div class="stat-card-icon">${E.carrot}</div><div class="stat-card-val">32</div><div class="stat-card-unit">товара</div></div>
      <div class="stat-card"><div class="stat-card-icon">${E.seedling}</div><div class="stat-card-val">18</div><div class="stat-card-unit">км</div></div>
      <div class="stat-card"><div class="stat-card-icon">${E.group}</div><div class="stat-card-val">847</div><div class="stat-card-unit">покупателей</div></div>
      <div class="stat-card"><div class="stat-card-icon">${E.check}</div><div class="stat-card-val">3</div><div class="stat-card-unit">сертификата</div></div>
    </div>
  </div>

  <!-- Products -->
  <section class="section">
    ${sectionHd('Товары фермера', '32 позиции', 'Смотреть все', 'catalog.html')}
    <div class="col-4">
      ${[
        { name:'Томаты черри',   price:280, emoji:E.tomato, farm:'КФХ Петровых', miles:18 },
        { name:'Огурцы свежие',  price:180, emoji:'🥒',     farm:'КФХ Петровых', miles:18 },
        { name:'Зелень ассорти', price:140, emoji:E.herb,   farm:'КФХ Петровых', miles:18 },
        { name:'Кабачок',        price:110, emoji:'🥬',     farm:'КФХ Петровых', miles:18 },
      ].map(p => productCard({ ...p, href:'product.html' })).join('')}
    </div>
  </section>
  `});
}

// ── S11: Search & Filters ─────────────────────────────────────────
function pageSearch() {
  return appShell({ active:'search', content:`
  <div class="page-header">
    <div class="page-title">Поиск и фильтры</div>
  </div>

  <!-- Search bar -->
  <div class="input input-lg" style="margin-bottom:32px;font-size:16px;cursor:text">
    ${I.search}<span class="input-value" style="font-size:16px">Что ищете? Например: «молоко», «томаты», «мёд»…</span>
  </div>

  <div style="display:flex;gap:32px;align-items:flex-start">

    <!-- Filter sidebar -->
    <div style="flex:0 0 280px;display:flex;flex-direction:column;gap:24px">

      <div class="filter-panel">
        <div class="filter-panel-title">${I.grid} Категория</div>
        <div class="filter-chips">
          ${['Все', 'Овощи', 'Фрукты', 'Молочное', 'Мясо', 'Зерновые', 'Мёд', 'Ягоды'].map((c,i) => chip(c, i===0)).join('')}
        </div>
      </div>

      <div class="filter-panel">
        <div class="filter-panel-title">${E.seedling} Пищевые мили (макс. км)</div>
        <div style="padding:8px 0">
          <div style="font-size:24px;font-weight:700;color:var(--color-primary);margin-bottom:8px">50 км</div>
          ${progressBar(50)}
          <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--color-text-muted);margin-top:4px">
            <span>5 км</span><span>200 км</span>
          </div>
        </div>
        ${btn('Карта ферм', { variant:'secondary', size:'sm', href:'farm-map.html', icon: I.map })}
      </div>

      <div class="filter-panel">
        <div class="filter-panel-title">${I.award} Сертификация</div>
        <div class="filter-chips">
          ${['Все', 'Органик', 'ГОСТ Р', 'ЭКО', 'БИО', 'Фермерское'].map(c => chip(c)).join('')}
        </div>
      </div>

      <div class="filter-panel">
        <div class="filter-panel-title">${I.filter} Сортировка</div>
        <div class="filter-chips" style="flex-direction:column;align-items:flex-start">
          ${['По популярности','По цене ↑','По цене ↓','Ближе всего','Новинки'].map((c,i) => chip(c, i===0)).join('')}
        </div>
      </div>

      <div style="display:flex;gap:8px">
        ${btn('Применить', { variant:'primary', full:true })}
        ${btn('Сбросить', { variant:'ghost' })}
      </div>
    </div>

    <!-- Results -->
    <div style="flex:1">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
        <div style="font-size:14px;color:var(--color-text-2)">Найдено <strong>83 товара</strong> в радиусе 50 км</div>
        ${btn('Карта ферм', { variant:'outline', size:'sm', href:'farm-map.html', icon: I.map })}
      </div>
      <div class="col-3">
        ${[
          { name:'Томаты черри',    price:280, emoji:E.tomato,  farm:'КФХ Петровых',  miles:18 },
          { name:'Молоко 3.5%',     price:120, emoji:E.milk,    farm:'Ферма Зорька',  miles:34 },
          { name:'Яйца С0',         price:190, emoji:E.egg,     farm:'Птицеферма Нива',miles:22 },
          { name:'Сыр козий',       price:520, emoji:E.cheese,  farm:'КФХ Козье',     miles:45 },
          { name:'Клубника',        price:380, emoji:E.berry,   farm:'КФХ Солнечное', miles:29 },
          { name:'Мёд цветочный',   price:490, emoji:E.honey,   farm:'Пасека Лесная', miles:50 },
        ].map(p => productCard({ ...p, href:'product.html' })).join('')}
      </div>
    </div>
  </div>
  `});
}

// ── S12: Farm Map ─────────────────────────────────────────────────
function pageFarmMap() {
  const pins = [
    { top:'35%', left:'38%', label:'КФХ Петровых', emoji:E.tractor },
    { top:'55%', left:'52%', label:'Ферма Зорька',  emoji:E.cow },
    { top:'25%', left:'60%', label:'Пасека Лесная', emoji:E.honey },
    { top:'65%', left:'30%', label:'Агро Нива',     emoji:E.grain },
    { top:'45%', left:'70%', label:'КФХ Солнечное', emoji:E.berry },
  ];

  return appShell({ active:'farm-map', content:`
  <div class="page-header">
    <div class="page-title">Карта ферм</div>
    <div class="page-subtitle">Фермы в радиусе 60 км от вас</div>
  </div>

  <!-- Controls -->
  <div style="display:flex;gap:16px;margin-bottom:24px;align-items:center;flex-wrap:wrap">
    <div class="input" style="flex:1;max-width:320px">${I.search}<span class="input-value">Поиск фермы…</span></div>
    ${selectField('50 км', ['10 км','25 км','50 км','100 км'], { label:'' })}
    <div class="filter-chips">
      ${chip('Все', true)}${chip('Овощи')}${chip('Молочное')}${chip('Мясо')}${chip('Мёд')}
    </div>
  </div>

  <!-- Map + list -->
  <div style="display:flex;gap:24px">

    <!-- Map -->
    <div class="map-box" style="flex:1;height:560px;position:relative">
      <div style="font-size:48px;opacity:.2">🗺️</div>
      <div style="position:absolute;inset:0;background:linear-gradient(145deg,#d4e8c0 0%,#b8d090 40%,#e8e0c0 70%,#c8d8a8 100%)"></div>
      ${pins.map(p => `
        <div class="map-pin" style="top:${p.top};left:${p.left}">
          <div style="background:var(--color-primary);color:#fff;border-radius:var(--r-full);padding:4px 10px;font-size:12px;font-weight:600;white-space:nowrap;box-shadow:var(--sh-md)">${p.emoji} ${p.label}</div>
          <div style="width:10px;height:10px;background:var(--color-primary);border-radius:50%;margin:2px auto"></div>
        </div>`).join('')}
      <div class="map-overlay">
        <div style="background:rgba(255,255,255,.9);border-radius:var(--r-full);padding:4px 14px;font-size:12px;color:var(--color-text-2)">
          📍 Вы здесь
        </div>
      </div>
    </div>

    <!-- Farms list -->
    <div style="flex:0 0 300px;display:flex;flex-direction:column;gap:12px;overflow-y:auto;max-height:560px">
      ${[
        { name:'КФХ Петровых',   region:'Тульская обл.',  miles:18, emoji:E.tractor, products:32 },
        { name:'Ферма Зорька',   region:'Калужская обл.', miles:34, emoji:E.cow,     products:18 },
        { name:'Пасека Лесная',  region:'Рязанская обл.', miles:56, emoji:E.honey,   products:7  },
        { name:'Агро Нива',      region:'Тульская обл.',  miles:41, emoji:E.grain,   products:24 },
        { name:'КФХ Солнечное',  region:'Московская обл.',miles:29, emoji:E.berry,   products:15 },
      ].map(f => `
        <a href="farmer.html" class="card card-p" style="display:flex;gap:12px;text-decoration:none;color:inherit">
          <div style="font-size:28px;flex-shrink:0">${f.emoji}</div>
          <div>
            <div style="font-weight:700;font-size:14px">${f.name}</div>
            <div style="font-size:12px;color:var(--color-text-2)">📍 ${f.region}</div>
            <div style="margin-top:4px;display:flex;gap:6px">
              ${milesTag(f.miles)}
              ${badge(`${f.products} товаров`, 'gray')}
            </div>
          </div>
        </a>`).join('')}
    </div>
  </div>
  `});
}

// ── S13: Cart ─────────────────────────────────────────────────────
function pageCart() {
  const items = [
    { name:'Томаты черри',    farm:'КФХ Петровых', price:280, emoji:E.tomato,  qty:2 },
    { name:'Молоко 3.5%',     farm:'Ферма Зорька', price:120, emoji:E.milk,    qty:1 },
    { name:'Яйца С0 (10 шт)',  farm:'Птицеферма Нива', price:190, emoji:E.egg, qty:1 },
  ];
  const subtotal = items.reduce((s,i) => s + i.price * i.qty, 0);

  return appShell({ active:'cart', content:`
  <div class="page-header">
    <div class="page-title">Корзина</div>
    <div class="page-subtitle">${items.length} позиции от 3 фермеров</div>
  </div>

  <div style="display:flex;gap:32px;align-items:flex-start">

    <!-- Items -->
    <div style="flex:1">
      <div class="card">
        ${items.map(i => cartItem(i)).join('')}
      </div>

      <!-- Group buys -->
      <div class="card card-p" style="margin-top:24px;background:var(--color-primary-bg);border-color:var(--color-primary)">
        <div style="display:flex;gap:16px;align-items:center">
          <div style="font-size:32px">${E.group}</div>
          <div>
            <div style="font-weight:700">Групповые закупки</div>
            <div style="font-size:13px;color:var(--color-text-2)">Пригласите друзей — получите скидку до 20%</div>
          </div>
          ${btn('Подробнее', { variant:'primary', size:'sm', href:'group-buys.html' })}
        </div>
      </div>
    </div>

    <!-- Summary -->
    <div style="flex:0 0 340px">
      <div class="card card-p" style="display:flex;flex-direction:column;gap:16px">
        <div style="font-size:18px;font-weight:700">Итого</div>

        ${inputField('Введите промокод', { label:'Промокод', icon: I.tag })}
        ${btn('Применить', { variant:'secondary', size:'sm' })}

        <hr class="divider">
        ${infoRow('Товары (4 шт)', `${subtotal} ₽`)}
        ${infoRow('Доставка', '150 ₽')}
        ${infoRow('Скидка промокод', '−0 ₽')}
        <hr class="divider">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div style="font-size:20px;font-weight:700">К оплате</div>
          <div style="font-size:24px;font-weight:700;color:var(--color-primary)">${subtotal + 150} ₽</div>
        </div>

        <div style="font-size:12px;color:var(--color-text-2);background:var(--color-surface-2);border-radius:var(--r-md);padding:12px">
          ${E.co2} Средние пищевые мили корзины: <strong>28 км</strong> — отлично для экологии!
        </div>

        ${btn('Перейти к оформлению', { variant:'primary', size:'lg', full:true, href:'checkout.html', icon: I.chevR })}
      </div>
    </div>
  </div>
  `});
}

// ── S14: Checkout ─────────────────────────────────────────────────
function pageCheckout() {
  return appShell({ active:'cart', content:`
  <div class="page-header">
    <div class="page-title">Оформление заказа</div>
  </div>

  <!-- Steps -->
  <div style="display:flex;gap:0;margin-bottom:40px">
    ${[['1','Корзина',false],['2','Доставка',true],['3','Оплата',false]].map(([n,l,a]) => `
      <div style="display:flex;align-items:center;gap:8px;padding:8px 20px;
        background:${a?'var(--color-primary)':'var(--color-surface-alt)'};
        color:${a?'#fff':'var(--color-text-2)'};font-size:13px;font-weight:600;
        ${n==='1'?'border-radius:var(--r-md) 0 0 var(--r-md)':''}
        ${n==='3'?'border-radius:0 var(--r-md) var(--r-md) 0':''}
        border:1px solid var(--color-border)">
        <span style="width:20px;height:20px;border-radius:50%;background:${a?'rgba(255,255,255,.3)':'var(--color-border)'};display:flex;align-items:center;justify-content:center;font-size:11px">${n}</span>
        ${l}
      </div>`).join('')}
  </div>

  <div style="display:flex;gap:32px;align-items:flex-start">
    <div style="flex:1;display:flex;flex-direction:column;gap:24px">

      <div class="card card-p">
        <div style="font-size:16px;font-weight:700;margin-bottom:16px">${I.pin} Адрес доставки</div>
        <div style="display:flex;flex-direction:column;gap:16px">
          ${inputField('г. Москва, ул. Садовая, д. 12, кв. 34', { label:'Адрес', icon: I.pin })}
          <div class="col-2">
            ${inputField('Москва', { label:'Город' })}
            ${inputField('115054',  { label:'Индекс' })}
          </div>
          ${inputField('Домофон 34#, 2-й этаж', { label:'Комментарий к адресу (необязательно)' })}
        </div>
      </div>

      <div class="card card-p">
        <div style="font-size:16px;font-weight:700;margin-bottom:16px">${I.calendar} Дата и время доставки</div>
        <div class="col-2">
          ${inputField('27 мая 2025', { label:'Дата', icon: I.calendar })}
          ${selectField('10:00 – 14:00', ['10:00–14:00','14:00–18:00','18:00–22:00'], { label:'Время' })}
        </div>
      </div>

      <div class="card card-p">
        <div style="font-size:16px;font-weight:700;margin-bottom:16px">${I.credit} Способ оплаты</div>
        ${selectField('Банковская карта', ['Банковская карта','СБП','Наложенный платёж'], { icon: I.credit })}
      </div>

      <div class="card card-p">
        <div style="font-size:16px;font-weight:700;margin-bottom:16px">💬 Комментарий к заказу</div>
        <div class="input" style="height:80px;align-items:flex-start;padding:12px">
          <span class="input-value">Оставьте у двери, позвоните заранее…</span>
        </div>
      </div>
    </div>

    <!-- Summary -->
    <div style="flex:0 0 300px">
      <div class="card card-p">
        <div style="font-weight:700;font-size:16px;margin-bottom:16px">Ваш заказ</div>
        ${[['Томаты черри ×2','560 ₽'],['Молоко ×1','120 ₽'],['Яйца С0 ×1','190 ₽']].map(([n,p]) =>
          `<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--color-border);font-size:13px">
            <span>${n}</span><span style="font-weight:600">${p}</span>
          </div>`).join('')}
        <hr class="divider">
        ${infoRow('Доставка','150 ₽')}
        <div style="display:flex;justify-content:space-between;margin-top:12px">
          <strong>Итого</strong>
          <strong style="color:var(--color-primary);font-size:18px">1 020 ₽</strong>
        </div>
        <div style="margin-top:16px">
          ${btn('Подтвердить заказ', { variant:'primary', size:'lg', full:true, href:'payment.html' })}
        </div>
      </div>
    </div>
  </div>
  `});
}

// ── S15: Payment ──────────────────────────────────────────────────
function pagePayment() {
  return appShell({ active:'cart', content:`
  <div style="max-width:480px;margin:0 auto;padding-top:40px">
    <div class="page-header" style="text-align:center">
      <div style="font-size:48px;margin-bottom:16px">${I.credit}</div>
      <div class="page-title">Оплата заказа</div>
      <div class="page-subtitle">Сумма к оплате: <strong style="color:var(--color-primary)">1 020 ₽</strong></div>
    </div>

    <div class="card card-p" style="display:flex;flex-direction:column;gap:20px">
      ${inputField('0000 0000 0000 0000', { label:'Номер карты', icon: I.credit })}
      <div class="col-2">
        ${inputField('MM/YY', { label:'Срок действия', icon: I.calendar })}
        ${inputField('CVV', { label:'CVV', icon: I.lock })}
      </div>
      ${inputField('ANNA SMIRNOVA', { label:'Имя на карте', icon: I.user })}

      <div style="background:var(--color-surface-2);border-radius:var(--r-md);padding:12px;font-size:12px;color:var(--color-text-2);display:flex;gap:8px">
        ${I.shield} Платёж защищён шифрованием TLS 1.3. Данные карты не хранятся на сервере.
      </div>

      ${btn('Оплатить 1 020 ₽', { variant:'primary', size:'lg', full:true, href:'orders.html' })}
      ${btn('Вернуться к оформлению', { variant:'ghost', full:true, href:'checkout.html' })}
    </div>
  </div>
  `});
}

// ── S16: Orders ───────────────────────────────────────────────────
function pageOrders() {
  const orders = [
    { id:'20482', date:'24 мая 2025, 12:34', status:'В пути',         total:1020, items:3 },
    { id:'20341', date:'17 мая 2025, 09:11', status:'Доставлен',      total:780,  items:2 },
    { id:'20198', date:'10 мая 2025, 15:47', status:'Доставлен',      total:1560, items:5 },
    { id:'20045', date:'3 мая 2025, 11:20',  status:'Отменён',        total:320,  items:1 },
  ];

  return appShell({ active:'orders', content:`
  <div class="page-header">
    <div class="page-title">Мои заказы</div>
  </div>

  <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap">
    ${['Все','В пути','Доставлен','Обрабатывается','Отменён'].map((s,i) => chip(s, i===0)).join('')}
  </div>

  <div class="card">
    ${orders.map(o => orderRow(o)).join('')}
  </div>
  `});
}

// ── S17: Order Detail ─────────────────────────────────────────────
function pageOrderDetail() {
  return appShell({ active:'orders', content:`
  <div class="page-header" style="display:flex;align-items:center;gap:16px">
    ${btn('← Назад', { variant:'ghost', href:'orders.html' })}
    <div>
      <div class="page-title">Заказ #20482</div>
      <div class="page-subtitle">24 мая 2025 · ${statusBadge('В пути')}</div>
    </div>
  </div>

  <div style="display:flex;gap:32px;align-items:flex-start">
    <div style="flex:1">

      <!-- Timeline -->
      <div class="card card-p" style="margin-bottom:24px">
        <div style="font-weight:700;margin-bottom:16px">${I.truck} Статус доставки</div>
        <div class="timeline">
          ${[
            ['Заказ принят',       '24 мая, 12:34', true],
            ['Фермер подтвердил',  '24 мая, 13:15', true],
            ['Передан в доставку', '24 мая, 15:00', true],
            ['В пути',             '25 мая, 09:00', true],
            ['Доставлен',          'Ожидается 25 мая, 12:00–16:00', false],
          ].map(([l,d,a]) => `
            <div class="timeline-item">
              <div class="timeline-dot${a?' active':''}">${a ? I.check : ''}</div>
              <div class="timeline-text">
                <div class="timeline-label">${l}</div>
                <div class="timeline-date">${d}</div>
              </div>
            </div>`).join('')}
        </div>
      </div>

      <!-- Items -->
      <div class="card">
        ${[
          { name:'Томаты черри',   farm:'КФХ Петровых', price:280, emoji:E.tomato, qty:2 },
          { name:'Молоко 3.5%',    farm:'Ферма Зорька', price:120, emoji:E.milk,   qty:1 },
          { name:'Яйца С0',        farm:'Птицеферма Нива', price:190, emoji:E.egg, qty:1 },
        ].map(i => cartItem(i)).join('')}
      </div>
    </div>

    <div style="flex:0 0 300px;display:flex;flex-direction:column;gap:16px">
      <div class="card card-p">
        <div style="font-weight:700;margin-bottom:12px">📍 Доставка</div>
        <div style="font-size:13px;color:var(--color-text-2)">г. Москва, ул. Садовая, д. 12, кв. 34</div>
        <div style="font-size:12px;color:var(--color-text-muted);margin-top:4px">25 мая · 12:00–16:00</div>
      </div>
      <div class="card card-p">
        <div style="font-weight:700;margin-bottom:12px">💰 Оплата</div>
        ${infoRow('Товары','870 ₽')}
        ${infoRow('Доставка','150 ₽')}
        <div style="display:flex;justify-content:space-between;padding-top:12px;font-weight:700">
          <span>Итого</span><span style="color:var(--color-primary)">1 020 ₽</span>
        </div>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${btn('Повторить заказ', { variant:'primary', full:true, href:'cart.html', icon: I.refresh })}
        ${btn('Оставить отзыв', { variant:'secondary', full:true, icon: I.edit2 })}
      </div>
    </div>
  </div>
  `});
}

// ── S18: Group Buys ───────────────────────────────────────────────
function pageGroupBuys() {
  const groups = [
    { name:'Картофель молодой 10 кг', emoji:E.potato,  current:11, target:20, discount:15 },
    { name:'Корзина овощей «Лето»',   emoji:E.basket,  current:7,  target:15, discount:20 },
    { name:'Молоко 10 л (3 недели)',  emoji:E.milk,    current:4,  target:10, discount:12 },
    { name:'Мёд цветочный 3 кг',      emoji:E.honey,   current:9,  target:12, discount:18 },
  ];

  return appShell({ active:'group-buys', content:`
  <div class="page-header">
    <div class="page-title">Групповые закупки</div>
    <div class="page-subtitle">Покупайте вместе — платите меньше</div>
  </div>

  <!-- Explainer -->
  <div style="display:flex;gap:24px;margin-bottom:40px">
    ${[
      [E.group,'Найдите группу','Выберите товар и вступите в уже активную группу покупателей'],
      [E.tag,  'Получите скидку','Чем больше участников — тем выгоднее цена для всех'],
      [E.truck,'Доставка вместе','Один заказ от фермера — экономия на логистике'],
    ].map(([e,t,d]) => `
      <div class="card card-p" style="flex:1;text-align:center">
        <div style="font-size:36px;margin-bottom:12px">${e}</div>
        <div style="font-weight:700;margin-bottom:8px">${t}</div>
        <div style="font-size:13px;color:var(--color-text-2)">${d}</div>
      </div>`).join('')}
  </div>

  <!-- Active groups -->
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
    ${sectionHd('Активные группы', `${groups.length} открытых группы`)}
    ${btn('+ Создать новую группу', { variant:'primary', href:'#create' })}
  </div>

  <div class="col-2" style="margin-bottom:40px">
    ${groups.map(g => groupCard(g)).join('')}
  </div>

  <!-- Create form -->
  <div class="card card-p" id="create">
    <div style="font-size:18px;font-weight:700;margin-bottom:20px">➕ Создать новую группу</div>
    <div style="display:flex;flex-direction:column;gap:16px;max-width:480px">
      ${inputField('Название группы закупки', { label:'Название' })}
      ${selectField('Выберите товар', [], { label:'Товар из каталога', icon: I.grid })}
      ${inputField('10', { label:'Нужное количество участников', icon: I.users })}
      ${btn('Создать группу', { variant:'primary', size:'lg', href:'cart.html' })}
    </div>
  </div>
  `});
}

// ── S19: Tours ────────────────────────────────────────────────────
function pageTours() {
  const tours = [
    { name:'День на молочной ферме',      date:'24 мая 2025', price:800,  farm:'Ферма Зорька',  emoji:E.cow,    seats:8  },
    { name:'Сбор клубники',               date:'1 июня 2025', price:600,  farm:'КФХ Петровых',  emoji:E.berry,  seats:15 },
    { name:'Пасека: мёд своими руками',   date:'8 июня 2025', price:1200, farm:'Пасека Лесная', emoji:E.honey,  seats:6  },
    { name:'Школа фермерства (1 день)',    date:'15 июня 2025',price:1500, farm:'Агро Нива',     emoji:E.tractor,seats:20 },
    { name:'Экскурсия по козьей ферме',   date:'22 июня 2025',price:700,  farm:'КФХ Козье',     emoji:'🐐',     seats:12 },
    { name:'Утренняя дойка + завтрак',    date:'29 июня 2025',price:900,  farm:'Ферма Зорька',  emoji:E.cow,    seats:10 },
  ];

  return appShell({ active:'tours', content:`
  <div class="page-header">
    <div class="page-title">Экскурсии на фермы</div>
    <div class="page-subtitle">Побывайте там, где растут ваши продукты</div>
  </div>

  <div style="display:flex;gap:16px;margin-bottom:32px;flex-wrap:wrap;align-items:flex-end">
    ${inputField('Любой регион', { label:'Регион', icon: I.map })}
    ${inputField('Любая дата', { label:'Дата', icon: I.calendar })}
    ${selectField('Любая ферма', [], { label:'Ферма' })}
    ${btn('Найти', { variant:'primary', size:'lg' })}
  </div>

  <div class="col-3">
    ${tours.map(t => tourCard({ ...t, href:'tour-detail.html' })).join('')}
  </div>
  `});
}

// ── S20: Tour Detail ──────────────────────────────────────────────
function pageTourDetail() {
  return appShell({ active:'tours', content:`
  ${imgBox('100%','320px', E.cow, 'День на молочной ферме', 'border-radius:var(--r-2xl)')}

  <div style="display:flex;gap:40px;align-items:flex-start;margin-top:32px">
    <div style="flex:1">
      <h1 style="font-family:var(--font-display);font-size:var(--fz-4xl);font-weight:700;margin-bottom:8px">День на молочной ферме</h1>
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px">
        ${badge('📅 24 мая 2025', 'gray')}
        ${badge('⏰ 10:00–17:00', 'gray')}
        ${badge('📍 Калужская обл., 34 км', 'gray')}
        ${badge('8 мест осталось', 'yellow')}
      </div>
      <p style="font-size:14px;color:var(--color-text-2);line-height:1.8;margin-bottom:24px">
        Проведите целый день на настоящей молочной ферме. Вы увидите утреннюю дойку, узнаете, как делают творог и сметану прямо из-под коровы, попробуете кормить телят и заберёте с собой литр парного молока.
      </p>
      <div>
        ${[
          ['Включено в стоимость','Трансфер от м. Теплый Стан, обед от фермы, дегустация, литр молока в подарок'],
          ['Программа дня','10:00 Встреча · 11:00 Экскурсия · 13:00 Обед · 14:30 Мастер-класс · 16:30 Дегустация'],
          ['Подходит для','Взрослых и детей от 5 лет'],
          ['Организатор','Ферма Зорька — Калужская обл.'],
        ].map(([l,v]) => infoRow(l,v)).join('')}
      </div>
    </div>

    <div style="flex:0 0 300px">
      <div class="card card-p" style="display:flex;flex-direction:column;gap:16px">
        <div style="font-size:28px;font-weight:700;color:var(--color-primary)">800 ₽ <span style="font-size:14px;color:var(--color-text-2);font-weight:400">/ чел</span></div>
        ${inputField('2', { label:'Количество участников', icon: I.users })}
        <div style="font-size:14px;color:var(--color-text-2)">Итого: <strong>1 600 ₽</strong></div>
        ${btn('Забронировать', { variant:'primary', size:'lg', full:true, href:'payment.html' })}
        ${btn('Добавить в избранное', { variant:'secondary', full:true, icon: I.heart })}
      </div>
    </div>
  </div>
  `});
}

// ── S21: Profile ──────────────────────────────────────────────────
function pageProfile() {
  return appShell({ active:'profile', content:`
  <div class="page-header">
    <div class="page-title">Профиль</div>
  </div>

  <div style="display:flex;gap:32px;align-items:flex-start">

    <!-- Avatar + nav -->
    <div style="flex:0 0 260px;display:flex;flex-direction:column;gap:8px">
      <div class="card card-p" style="text-align:center;margin-bottom:8px">
        <div style="width:80px;height:80px;border-radius:50%;background:var(--color-primary-light);
          display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700;
          color:#fff;margin:0 auto 12px">АС</div>
        <div style="font-weight:700;font-size:16px">Анна Смирнова</div>
        <div style="font-size:12px;color:var(--color-text-2)">anna@example.com</div>
        <div style="margin-top:8px">${badge('Покупатель', 'primary')}</div>
      </div>
      ${[
        [I.pkg,     'Мои заказы',        'orders.html'],
        [I.heart,   'Избранное',         'favorites.html'],
        [I.leaf,    'Подписки',          'subscriptions.html'],
        [I.pin,     'Адреса доставки',   'addresses.html'],
        [I.chart,   'CO₂ статистика',    'co2.html'],
        [I.settings,'Настройки',          'settings.html'],
      ].map(([ic,l,h]) => `<a href="${h}" class="nav-item" style="border-radius:var(--r-md);background:var(--color-surface);border:1px solid var(--color-border);color:var(--color-text)">${ic}<span>${l}</span>${I.chevR}</a>`).join('')}
      <a href="login.html" class="nav-item" style="color:var(--color-status-err);background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--r-md)">${I.logOut}<span>Выйти</span></a>
    </div>

    <!-- Stats + recent orders -->
    <div style="flex:1;display:flex;flex-direction:column;gap:24px">
      <div class="col-4">
        <div class="stat-card"><div class="stat-card-icon">${E.bag}</div><div class="stat-card-val">24</div><div class="stat-card-unit">заказа</div></div>
        <div class="stat-card"><div class="stat-card-icon">${E.heart}</div><div class="stat-card-val">18</div><div class="stat-card-unit">в избранном</div></div>
        <div class="stat-card"><div class="stat-card-icon">${E.co2}</div><div class="stat-card-val">12.4</div><div class="stat-card-unit">кг CO₂ сэкономлено</div></div>
        <div class="stat-card"><div class="stat-card-icon">${E.farm}</div><div class="stat-card-val">8</div><div class="stat-card-unit">фермеров</div></div>
      </div>

      <div class="card">
        <div style="padding:16px;border-bottom:1px solid var(--color-border);font-weight:700">Последние заказы</div>
        ${[
          { id:'20482', date:'24 мая 2025', status:'В пути',    total:1020, items:3 },
          { id:'20341', date:'17 мая 2025', status:'Доставлен', total:780,  items:2 },
        ].map(o => orderRow(o)).join('')}
        <div style="padding:12px 16px">${btn('Все заказы', { variant:'ghost', href:'orders.html' })}</div>
      </div>
    </div>
  </div>
  `});
}

// ── S22: Favorites ────────────────────────────────────────────────
function pageFavorites() {
  return appShell({ active:'favorites', content:`
  <div class="page-header">
    <div class="page-title">Избранное</div>
    <div class="page-subtitle">18 товаров и ферм</div>
  </div>
  <div style="display:flex;gap:12px;margin-bottom:24px">
    ${chip('Товары (14)', true)} ${chip('Фермеры (4)')}
  </div>
  <div class="col-4">
    ${[
      { name:'Томаты черри',    price:280, emoji:E.tomato,  farm:'КФХ Петровых',   miles:18 },
      { name:'Молоко 3.5%',     price:120, emoji:E.milk,    farm:'Ферма Зорька',   miles:34 },
      { name:'Мёд гречишный',   price:650, emoji:E.honey,   farm:'Пасека Лесная',  miles:56 },
      { name:'Яйца С0',         price:190, emoji:E.egg,     farm:'Птицеферма Нива',miles:22 },
    ].map(p => productCard({ ...p, href:'product.html' })).join('')}
  </div>
  `});
}

// ── S23: Subscriptions ────────────────────────────────────────────
function pageSubscriptions() {
  return appShell({ active:'subscriptions', content:`
  <div class="page-header">
    <div class="page-title">Подписки</div>
    <div class="page-subtitle">Регулярная доставка сезонных корзин</div>
  </div>

  <!-- Active -->
  <section class="section">
    ${sectionHd('Активные подписки')}
    <div class="col-2">
      ${[
        { name:'Весенняя корзина', items:'Редис, зелень, шпинат', price:890,  emoji:E.basket, status:'Активна',       next:'28 мая' },
        { name:'Молочная корзина', items:'Молоко, кефир, творог', price:1240, emoji:E.milk,   status:'Приостановлена',next:'—' },
      ].map(s => `
        <div class="card card-p">
          <div style="display:flex;gap:16px;align-items:flex-start;margin-bottom:16px">
            ${imgBox('64px','64px', s.emoji, '')}
            <div>
              <div style="font-weight:700">${s.name}</div>
              <div style="font-size:12px;color:var(--color-text-2);margin-top:2px">${s.items}</div>
              <div style="margin-top:8px;display:flex;gap:8px">
                ${statusBadge(s.status)}
                ${badge(`Следующая: ${s.next}`, 'gray')}
              </div>
            </div>
          </div>
          <div style="display:flex;gap:8px">
            ${btn('Приостановить', { variant:'secondary', size:'sm', icon: I.refresh })}
            ${btn('Отменить', { variant:'danger', size:'sm', icon: I.x16 })}
          </div>
        </div>`).join('')}
    </div>
  </section>

  <!-- New subscription -->
  <section class="section">
    ${sectionHd('Оформить новую подписку')}
    <div class="col-2" style="margin-bottom:32px">
      ${[
        { name:'Весенняя корзина', items:'Редис, зелень, шпинат, укроп', price:890,  emoji:E.basket },
        { name:'Молочная корзина', items:'Молоко, кефир, творог, сметана',price:1240, emoji:E.milk   },
        { name:'Овощная корзина',  items:'Огурцы, помидоры, кабачок',    price:760,  emoji:E.carrot },
        { name:'Ягодная корзина',  items:'Клубника, черника, малина',     price:1100, emoji:E.berry  },
      ].map(b => basketCard({ ...b, href:'subscriptions.html' })).join('')}
    </div>

    <div class="card card-p" style="max-width:540px">
      <div style="font-size:16px;font-weight:700;margin-bottom:16px">Параметры доставки</div>
      ${selectField('Еженедельно', ['Еженедельно','Раз в 2 недели','Раз в месяц'], { label:'Периодичность' })}
      <div style="margin-top:16px">
        ${inputField('г. Москва, ул. Садовая, д. 12', { label:'Адрес доставки', icon: I.pin })}
      </div>
      <div style="margin-top:16px">
        ${btn('Оформить подписку', { variant:'primary', size:'lg', href:'payment.html' })}
      </div>
    </div>
  </section>
  `});
}

// ── S24: Addresses ────────────────────────────────────────────────
function pageAddresses() {
  return appShell({ active:'addresses', content:`
  <div class="page-header">
    <div class="page-title">Адреса доставки</div>
  </div>
  <div style="display:flex;flex-direction:column;gap:16px;max-width:600px">
    ${[
      { label:'Дом',  addr:'г. Москва, ул. Садовая, д. 12, кв. 34', default:true  },
      { label:'Работа',addr:'г. Москва, Проспект Мира, д. 45, оф. 201', default:false },
    ].map(a => `
      <div class="card card-p">
        <div style="display:flex;align-items:flex-start;gap:12px">
          <div style="font-size:24px">${a.default ? E.farm : '🏢'}</div>
          <div style="flex:1">
            <div style="display:flex;align-items:center;gap:8px">
              <span style="font-weight:700">${a.label}</span>
              ${a.default ? badge('Основной', 'primary') : ''}
            </div>
            <div style="font-size:13px;color:var(--color-text-2);margin-top:4px">${a.addr}</div>
          </div>
          <div style="display:flex;gap:8px">
            ${btn('', { variant:'ghost', size:'sm', icon: I.edit2 })}
            ${btn('', { variant:'ghost', size:'sm', icon: I.x16 })}
          </div>
        </div>
      </div>`).join('')}
    <div style="margin-top:8px">
      ${btn('+ Добавить адрес', { variant:'outline' })}
    </div>
  </div>
  `});
}

// ── S25: CO2 Stats ────────────────────────────────────────────────
function pageCO2() {
  return appShell({ active:'co2', content:`
  <div class="page-header">
    <div class="page-title">CO₂ статистика</div>
    <div class="page-subtitle">Ваш экологический вклад с Местными Продуктами</div>
  </div>

  <div class="col-4" style="margin-bottom:40px">
    <div class="stat-card"><div class="stat-card-icon">🌱</div><div class="stat-card-val">12.4</div><div class="stat-card-unit">кг CO₂</div><div class="stat-card-label">сэкономлено</div></div>
    <div class="stat-card"><div class="stat-card-icon">🚛</div><div class="stat-card-val">248</div><div class="stat-card-unit">км</div><div class="stat-card-label">средние мили</div></div>
    <div class="stat-card"><div class="stat-card-icon">🌳</div><div class="stat-card-val">0.6</div><div class="stat-card-unit">дерево</div><div class="stat-card-label">эквивалент посадки</div></div>
    <div class="stat-card"><div class="stat-card-icon">🏡</div><div class="stat-card-val">8</div><div class="stat-card-unit">ферм</div><div class="stat-card-label">поддержано</div></div>
  </div>

  <div class="col-2">
    <div class="card card-p">
      <div style="font-weight:700;margin-bottom:16px">📊 CO₂ по месяцам</div>
      <div style="display:flex;flex-direction:column;gap:12px">
        ${[['Март','1.2',30],['Апрель','3.4',60],['Май','7.8',90]].map(([m,v,p]) => `
          <div>
            <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px">
              <span>${m}</span><span style="color:var(--color-primary);font-weight:600">−${v} кг</span>
            </div>
            ${progressBar(p)}
          </div>`).join('')}
      </div>
    </div>

    <div class="card card-p">
      <div style="font-weight:700;margin-bottom:16px">🛒 Топ товаров по экологичности</div>
      ${[
        [E.tomato,'Томаты черри',   '18 км','−0.8 кг CO₂'],
        [E.milk,  'Молоко 3.5%',   '34 км','−1.2 кг CO₂'],
        [E.egg,   'Яйца С0',       '22 км','−0.5 кг CO₂'],
        [E.honey, 'Мёд гречишный', '56 км','−2.1 кг CO₂'],
      ].map(([em,n,km,co]) => `
        <div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--color-border)">
          <span style="font-size:20px">${em}</span>
          <div style="flex:1"><div style="font-size:13px;font-weight:600">${n}</div><div style="font-size:11px;color:var(--color-text-muted)">${km}</div></div>
          <span style="font-size:12px;color:var(--color-status-ok);font-weight:600">${co}</span>
        </div>`).join('')}
    </div>
  </div>
  `});
}

// ── S26: Settings ─────────────────────────────────────────────────
function pageSettings() {
  return appShell({ active:'settings', content:`
  <div class="page-header">
    <div class="page-title">Настройки</div>
  </div>
  <div style="max-width:600px;display:flex;flex-direction:column;gap:24px">

    <div class="card card-p">
      <div style="font-weight:700;font-size:16px;margin-bottom:16px">${I.user} Личные данные</div>
      ${inputField('Анна Смирнова', { label:'Имя', icon: I.user })}
      <div style="margin-top:16px">${inputField('anna@example.com', { label:'Email', icon: I.mail })}</div>
      <div style="margin-top:16px">${inputField('+7 (900) 123-45-67', { label:'Телефон', icon: I.phone })}</div>
      <div style="margin-top:16px">${btn('Сохранить изменения', { variant:'primary' })}</div>
    </div>

    <div class="card card-p">
      <div style="font-weight:700;font-size:16px;margin-bottom:16px">${I.lock} Безопасность</div>
      ${inputField('••••••••', { label:'Текущий пароль', icon: I.lock })}
      <div style="margin-top:16px">${inputField('••••••••', { label:'Новый пароль', icon: I.lock })}</div>
      <div style="margin-top:16px">${btn('Изменить пароль', { variant:'secondary' })}</div>
    </div>

    <div class="card card-p">
      <div style="font-weight:700;font-size:16px;margin-bottom:16px">${I.bell} Уведомления</div>
      ${[
        ['Новые акции и скидки',      true],
        ['Обновления заказа',          true],
        ['Новые товары от фермеров',   false],
        ['Групповые закупки',          true],
        ['Экскурсии поблизости',       false],
      ].map(([l,on]) => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--color-border)">
          <span style="font-size:14px">${l}</span>
          <div style="width:40px;height:22px;border-radius:11px;background:${on?'var(--color-primary)':'var(--color-border)'};cursor:pointer;position:relative">
            <div style="width:18px;height:18px;border-radius:50%;background:#fff;position:absolute;top:2px;${on?'right:2px':'left:2px'};transition:left .2s"></div>
          </div>
        </div>`).join('')}
    </div>
  </div>
  `});
}

// ════════════════════════════════════════════════════════════════════
// SECTION 8 — HTML PAGE WRAPPER
// ════════════════════════════════════════════════════════════════════

function htmlPage(title, body) {
  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=1440">
  <title>${title} — Местные Продукты</title>
  <style>${BASE_CSS}</style>
</head>
<body>
${body}
</body>
</html>`;
}

// ════════════════════════════════════════════════════════════════════
// SECTION 9 — SCREEN REGISTRY
// ════════════════════════════════════════════════════════════════════

const SCREENS = [
  { id:'login',        title:'Вход',                    gen: pageLogin        },
  { id:'register',     title:'Регистрация',              gen: pageRegister     },
  { id:'recovery',     title:'Восстановление пароля',   gen: pageRecovery     },
  { id:'confirm-code', title:'Подтверждение кода',       gen: pageConfirmCode  },
  { id:'new-password', title:'Новый пароль',             gen: pageNewPassword  },
  { id:'onboarding',   title:'Онбординг',                gen: pageOnboarding   },
  { id:'home',         title:'Главная страница',         gen: pageHome         },
  { id:'catalog',      title:'Каталог',                  gen: pageCatalog      },
  { id:'product',      title:'Карточка товара',          gen: pageProduct      },
  { id:'farmer',       title:'Профиль фермера',          gen: pageFarmer       },
  { id:'search',       title:'Поиск и фильтры',          gen: pageSearch       },
  { id:'farm-map',     title:'Карта ферм',               gen: pageFarmMap      },
  { id:'cart',         title:'Корзина',                  gen: pageCart         },
  { id:'checkout',     title:'Оформление заказа',        gen: pageCheckout     },
  { id:'payment',      title:'Оплата',                   gen: pagePayment      },
  { id:'orders',       title:'Мои заказы',               gen: pageOrders       },
  { id:'order-detail', title:'Детали заказа',            gen: pageOrderDetail  },
  { id:'group-buys',   title:'Групповые закупки',        gen: pageGroupBuys    },
  { id:'tours',        title:'Экскурсии',                gen: pageTours        },
  { id:'tour-detail',  title:'Детали экскурсии',         gen: pageTourDetail   },
  { id:'profile',      title:'Профиль',                  gen: pageProfile      },
  { id:'favorites',    title:'Избранное',                gen: pageFavorites    },
  { id:'subscriptions',title:'Подписки',                 gen: pageSubscriptions},
  { id:'addresses',    title:'Адреса доставки',          gen: pageAddresses    },
  { id:'co2',          title:'CO₂ статистика',           gen: pageCO2          },
  { id:'settings',     title:'Настройки',                gen: pageSettings     },
];

// ════════════════════════════════════════════════════════════════════
// SECTION 10 — BUILD
// ════════════════════════════════════════════════════════════════════

function build() {
  if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, { recursive: true });

  // 1) Individual files
  for (const s of SCREENS) {
    const body = s.gen();
    fs.writeFileSync(path.join(OUT, `${s.id}.html`), htmlPage(s.title, body), 'utf8');
    console.log(`  ✓ ${s.id}.html`);
  }

  // 2) Combined file (all screens stacked, for html.to.design import)
  const combinedParts = SCREENS.map((s, idx) => {
    const body = s.gen();
    return `
<!-- ═══════════════════════════════════════════════════════════
     SCREEN ${String(idx + 1).padStart(2,'0')}: ${s.title.toUpperCase()}
     id: ${s.id}
═══════════════════════════════════════════════════════════ -->
<div class="combined-separator">
  <div>
    <div class="combined-screen-label">${s.title}</div>
    <div class="combined-screen-id">Экран ${idx + 1} / ${SCREENS.length} · ${s.id}</div>
  </div>
</div>
<div style="background:var(--color-bg);min-width:1440px">
${body}
</div>`;
  }).join('\n');

  const combinedHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=1440">
  <title>Местные Продукты — Все экраны (Figma import)</title>
  <style>
    ${BASE_CSS}
    body { min-width: 1440px; }
    .combined-separator {
      position: sticky;
      top: 0;
      z-index: 9999;
    }
  </style>
</head>
<body>
${combinedParts}
</body>
</html>`;

  fs.writeFileSync(path.join(OUT, '_combined.html'), combinedHTML, 'utf8');
  console.log(`  ✓ _combined.html  (${SCREENS.length} screens)`);

  // 3) Index / navigation hub
  const indexHTML = htmlPage('Навигация', `
<div style="min-height:100vh;background:var(--color-sidebar-bg);display:flex;align-items:center;justify-content:center;padding:64px">
  <div style="max-width:900px;width:100%">
    <div style="text-align:center;margin-bottom:48px">
      <div style="font-size:64px">🌿</div>
      <h1 style="font-family:var(--font-display);font-size:40px;font-weight:700;color:#fff;margin-top:16px">Местные Продукты</h1>
      <p style="color:var(--color-sidebar-text);margin-top:8px">Wireframe навигация · ${SCREENS.length} экранов</p>
    </div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
      ${SCREENS.map((s,i) => `
        <a href="${s.id}.html" style="background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);
          border-radius:var(--r-lg);padding:16px;text-decoration:none;color:#fff;
          transition:background .15s;display:flex;flex-direction:column;gap:6px"
          onmouseover="this.style.background='rgba(255,255,255,.13)'" onmouseout="this.style.background='rgba(255,255,255,.07)'">
          <div style="font-size:11px;color:rgba(255,255,255,.4);letter-spacing:.06em">S${String(i+1).padStart(2,'0')}</div>
          <div style="font-size:14px;font-weight:600">${s.title}</div>
          <div style="font-size:11px;color:rgba(255,255,255,.5)">${s.id}.html</div>
        </a>`).join('')}
    </div>
    <div style="text-align:center;margin-top:32px">
      <a href="_combined.html" style="display:inline-flex;align-items:center;gap:8px;
        background:var(--color-primary);color:#fff;border-radius:var(--r-full);
        padding:12px 32px;font-weight:700;font-size:16px;text-decoration:none">
        🗂️ Открыть _combined.html (Figma import)
      </a>
    </div>
  </div>
</div>`);

  fs.writeFileSync(path.join(OUT, 'index.html'), indexHTML, 'utf8');
  console.log(`  ✓ index.html`);

  console.log(`\n✅ Build complete → ${OUT}`);
  console.log(`   ${SCREENS.length} individual screens + _combined.html + index.html`);
}

build();