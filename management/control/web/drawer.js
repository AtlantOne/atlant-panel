'use strict';
(() => {
  const toggle=document.getElementById('open-navigation'),close=document.getElementById('close-navigation'),sidebar=document.getElementById('panel-sidebar'),backdrop=document.getElementById('navigation-backdrop'),content=document.getElementById('content');
  const mobile=matchMedia('(max-width:800px)');
  function setOpen(open,restore=true){
    open=!!open&&mobile.matches&&document.body.hasAttribute('data-authenticated');
    document.body.classList.toggle('navigation-open',open);toggle.setAttribute('aria-expanded',String(open));backdrop.hidden=!open;content.inert=open;
    if(mobile.matches)sidebar.inert=!open;else sidebar.inert=false;
    if(open)close.focus();else if(restore&&mobile.matches&&document.body.hasAttribute('data-authenticated'))toggle.focus();
  }
  toggle.addEventListener('click',()=>setOpen(true));close.addEventListener('click',()=>setOpen(false));backdrop.addEventListener('click',()=>setOpen(false));
  document.getElementById('navigation').addEventListener('click',event=>{if(event.target.closest('button'))setOpen(false);});
  document.addEventListener('keydown',event=>{
    if(!document.body.classList.contains('navigation-open'))return;
    if(event.key==='Escape'){event.preventDefault();setOpen(false);}
    if(event.key==='Tab'){
      const focusable=[...sidebar.querySelectorAll('button:not([hidden]),summary,a[href]')].filter(node=>node.getClientRects().length&&!node.disabled);
      const first=focusable[0],last=focusable.at(-1);
      if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}
    }
  });
  mobile.addEventListener('change',()=>setOpen(false,false));
  new MutationObserver(()=>{if(!document.body.hasAttribute('data-authenticated'))setOpen(false,false);}).observe(document.body,{attributes:true,attributeFilter:['data-authenticated']});
  setOpen(false,false);
})();
