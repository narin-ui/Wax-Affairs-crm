# SEO Update – Wiesbaden Pagina
## Datum: 15 april 2026

**Pagina:** /pages/wiesbaden  
**Shopify ID:** 698868007244  
**Admin URL:** https://admin.shopify.com/store/cfpdfy-jv/pages/698868007244

---

## Te implementeren wijzigingen

### Meta Title (max 60 tekens)
```
Waxing Wiesbaden | WAX AFFAIRS Studio Bahnhofstraße
```
*(51 tekens — optimaal)*

### Meta Description (max 155 tekens)
```
Premium Waxing in Wiesbaden, Bahnhofstraße 25. Brazilian Wax, Bein- & Gesichtswaxing. 100% natürliche Produkte. Termin per WhatsApp oder online.
```
*(144 tekens — optimaal)*

---

## Implementatie-instructies (handmatig of via JS)

1. Navigeer naar: https://admin.shopify.com/store/cfpdfy-jv/pages/698868007244
2. Klik op de "Edit" knop naast SEO (onderaan de pagina)
3. Pas de meta title en description aan
4. Sla op met Cmd+S

**JS-methode (als handmatige edit niet werkt):**
```javascript
// Open SEO edit paneel
document.querySelector('s-internal-button[accessibilitylabel="Edit"]')?.shadowRoot?.querySelector('button')?.click();

// Na het openen (~1 seconde wachten):
// Title instellen
let titleInput = document.querySelector('input[name="page[metafields][global][title_tag]"]');
Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(titleInput, 'Waxing Wiesbaden | WAX AFFAIRS Studio Bahnhofstraße');
titleInput.dispatchEvent(new Event('input', { bubbles: true }));

// Description instellen
let descInput = document.querySelector('textarea[name="page[metafields][global][description_tag]"]');
Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set.call(descInput, 'Premium Waxing in Wiesbaden, Bahnhofstraße 25. Brazilian Wax, Bein- & Gesichtswaxing. 100% natürliche Produkte. Termin per WhatsApp oder online.');
descInput.dispatchEvent(new Event('input', { bubbles: true }));
```

---

## Status
- [ ] Geïmplementeerd in Shopify
- Reden niet geïmplementeerd: Chrome extension niet verbonden tijdens geautomatiseerde run (15-04-2026)
