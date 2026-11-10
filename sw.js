/* Abu Hamza — cache-first app shell, connectivity-independent after first visit. */
const CACHE='abu-hamza-pwa-shell-v2';
const APP=['./','./index.html','./manifest.webmanifest','./icons/icon-192.png','./icons/icon-512.png'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(APP)).then(()=>self.skipWaiting())));
self.addEventListener('activate', event => event.waitUntil((async()=>{
 const names=await caches.keys();await Promise.all(names.filter(n=>n.startsWith('abu-hamza-pwa-shell-')&&n!==CACHE).map(n=>caches.delete(n)));
 await self.clients.claim();
})()));
self.addEventListener('fetch',event=>{
 const req=event.request,url=new URL(req.url);
 if(req.method!=='GET'||url.origin!==self.location.origin)return;
 if(req.mode==='navigate'){
   event.respondWith((async()=>{
     const cache=await caches.open(CACHE);
     const saved=await cache.match('./index.html');
     try{const fresh=await fetch(req);if(fresh.ok)cache.put('./index.html',fresh.clone());return fresh}catch{return saved||new Response('التطبيق غير مخزّن على هذا الجهاز. افتح التطبيق مرة بالإنترنت.',{status:503,headers:{'Content-Type':'text/plain;charset=utf-8'}})}
   })());return;
 }
 if(/\.(png|webmanifest|html|js)$/i.test(url.pathname))event.respondWith((async()=>{const cached=await caches.match(req);if(cached)return cached;try{const r=await fetch(req);if(r.ok){const c=await caches.open(CACHE);c.put(req,r.clone())}return r}catch{return cached||Response.error()}})());
});
