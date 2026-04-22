"""Voeg i18n toe aan sidebar + page headers + 'Nieuwe X' knoppen + section-kopjes."""
import re
p = '/Users/lisannegarretsen/wax-affairs-crm/index.html'
s = open(p, encoding='utf-8').read()
orig = s

# ══════════════════════════════════════════════════════════════
# 1. VOEG MISSENDE KEYS TOE AAN NL EN DE DICTIONARIES
# ══════════════════════════════════════════════════════════════

new_nl_keys = """
    // Sidebar navigatie (nav labels + dividers)
    navDashboard:'Dashboard',navStudios:'Studios',navAcademy:'Academy',navProducten:'Producten',
    navTeam:'Team',navUrenregistratie:'Urenregistratie',navFinancieel:'Financieel',
    navAgenda:'Agenda',navTaken:'Taken',navMarketing:'Marketing',navFriendchise:'Friendchise Pitch',
    navPipeline:'Pipeline',navBusinessplan:'Businessplan',
    divFranchise:'Franchise',divOrganisatie:'Organisatie',divPlanning:'Planning',
    divSalesMarketing:'Sales & Marketing',divStrategie:'Strategie',
    uitloggen:'Uitloggen',
    // Page headers
    hKlanten:'Klanten',hFranchisees:'Franchisees',hPipeline:'Pipeline',hStudenten:'Studenten',
    hCohorten:'Cohorten',hStudios:'Studios',hServices:'Services',hAgenda:'Agenda',
    hProducten:'Producten',hBestellingen:'Bestellingen',hLeveranciers:'Leveranciers',
    hLeads:'Leads',hVoorraad:'Voorraad',hTeam:'Team',hTaken:'Taken',hNotities:'Notities',
    hMarketing:'Marketing',hAcademy:'Academy',hPersoneel:'Urenregistratie',hFinancieel:'Financieel',
    hVasteLasten:'Vaste Lasten',hBusinessplan:'Businessplan',hKomendeAfspraken:'Komende Afspraken',
    // Nieuwe X knoppen
    btnNieuweAfspraak:'+ Nieuwe Afspraak',btnNieuweStudio:'+ Nieuwe Studio',btnNieuweService:'+ Nieuwe Service',
    btnNieuweFranchisee:'+ Nieuwe Franchisee',btnNieuweLead:'+ Nieuwe Lead',btnNieuweStudent:'+ Nieuwe Student',
    btnNieuwCohort:'+ Nieuw Cohort',btnNieuweBestelling:'+ Nieuwe Bestelling',btnNieuweLeverancier:'+ Nieuwe Leverancier',
    btnNieuweKlant:'+ Nieuwe Klant',btnNieuwProduct:'+ Nieuw Product',btnAfspraak:'+ Afspraak',
    // Directie overzicht buttons
    btnDirectieOverzicht:'📊 Directie Overzicht',btnOmzetDetails:'💶 Omzet Details',
    btnKosten:'🏠 Kosten',btnWinstVerlies:'📈 Winst & Verlies',
    // Algemeen
    vandaagLabel:'Vandaag',
"""

new_de_keys = """
    // Sidebar navigatie
    navDashboard:'Dashboard',navStudios:'Studios',navAcademy:'Academy',navProducten:'Produkte',
    navTeam:'Team',navUrenregistratie:'Zeiterfassung',navFinancieel:'Finanzen',
    navAgenda:'Kalender',navTaken:'Aufgaben',navMarketing:'Marketing',navFriendchise:'Friendchise Pitch',
    navPipeline:'Pipeline',navBusinessplan:'Businessplan',
    divFranchise:'Franchise',divOrganisatie:'Organisation',divPlanning:'Planung',
    divSalesMarketing:'Vertrieb & Marketing',divStrategie:'Strategie',
    uitloggen:'Abmelden',
    // Page headers
    hKlanten:'Kunden',hFranchisees:'Franchisees',hPipeline:'Pipeline',hStudenten:'Studenten',
    hCohorten:'Kohorten',hStudios:'Studios',hServices:'Leistungen',hAgenda:'Kalender',
    hProducten:'Produkte',hBestellingen:'Bestellungen',hLeveranciers:'Lieferanten',
    hLeads:'Leads',hVoorraad:'Bestand',hTeam:'Team',hTaken:'Aufgaben',hNotities:'Notizen',
    hMarketing:'Marketing',hAcademy:'Academy',hPersoneel:'Zeiterfassung',hFinancieel:'Finanzen',
    hVasteLasten:'Fixkosten',hBusinessplan:'Businessplan',hKomendeAfspraken:'Kommende Termine',
    // Nieuwe X knoppen
    btnNieuweAfspraak:'+ Neuer Termin',btnNieuweStudio:'+ Neues Studio',btnNieuweService:'+ Neue Leistung',
    btnNieuweFranchisee:'+ Neuer Franchisee',btnNieuweLead:'+ Neuer Lead',btnNieuweStudent:'+ Neuer Student',
    btnNieuwCohort:'+ Neue Kohorte',btnNieuweBestelling:'+ Neue Bestellung',btnNieuweLeverancier:'+ Neuer Lieferant',
    btnNieuweKlant:'+ Neue Kundin',btnNieuwProduct:'+ Neues Produkt',btnAfspraak:'+ Termin',
    // Directie
    btnDirectieOverzicht:'📊 Direktionsübersicht',btnOmzetDetails:'💶 Umsatzdetails',
    btnKosten:'🏠 Kosten',btnWinstVerlies:'📈 Gewinn & Verlust',
    // Algemeen
    vandaagLabel:'Heute',
"""

# Injecteer in NL dict — zoek de comment "// Friendchise Pitch" binnen NL en voeg ervoor in
nl_anchor = "    // Friendchise Pitch\n    friendchisePitch:'Friendchise Pitch',presentatieVoorLeads:'Presentatie voor franchise leads"
if nl_anchor in s:
    s = s.replace(nl_anchor, new_nl_keys + nl_anchor)
    print('✓ NL keys toegevoegd')
else:
    print('! NL anker niet gevonden')

# Injecteer in DE dict — zoek de parallelle comment
de_anchor = "    friendchisePitch:'Friendchise Pitch',presentatieVoorLeads:'Präsentation für Franchise-Leads"
if de_anchor in s:
    s = s.replace(de_anchor, new_de_keys + "    " + de_anchor)
    print('✓ DE keys toegevoegd')
else:
    # Probeer het zelfde patroon als NL met vaste anker
    de_anchor2 = "  de: {"
    # We voegen vóór 'friendchisePitch' in de-sectie toe
    # Ander anker: nogmaals zoeken in DE-context
    m = re.search(r"(  de:\s*\{.+?)(friendchisePitch:)", s, re.DOTALL)
    if m:
        s = s[:m.start(2)] + new_de_keys.replace('// Algemeen\n    vandaagLabel:', '// Algemeen\n    vandaagLabel:') + '\n    ' + m.group(2) + s[m.end(2):]
        print('✓ DE keys toegevoegd via regex fallback')
    else:
        print('! DE anker niet gevonden')

# ══════════════════════════════════════════════════════════════
# 2. PATCH SIDEBAR: vervang <span class="text-sm">X</span> door data-t variant
# ══════════════════════════════════════════════════════════════

sidebar_replacements = [
    # (oud, nieuw)
    ('<span class="icon text-lg">📊</span><span class="text-sm">Dashboard</span>',
     '<span class="icon text-lg">📊</span><span class="text-sm" data-t="navDashboard">Dashboard</span>'),
    ('<span class="icon text-lg">💈</span><span class="text-sm">Studios</span>',
     '<span class="icon text-lg">💈</span><span class="text-sm" data-t="navStudios">Studios</span>'),
    ('<span class="icon text-lg">🎓</span><span class="text-sm">Academy</span>',
     '<span class="icon text-lg">🎓</span><span class="text-sm" data-t="navAcademy">Academy</span>'),
    ('<span class="icon text-lg">📦</span><span class="text-sm">Producten</span>',
     '<span class="icon text-lg">📦</span><span class="text-sm" data-t="navProducten">Producten</span>'),
    ('<span class="icon text-lg">👩\u200d💼</span><span class="text-sm">Team</span>',
     '<span class="icon text-lg">👩\u200d💼</span><span class="text-sm" data-t="navTeam">Team</span>'),
    ('<span class="icon text-lg">🕐</span><span class="text-sm">Urenregistratie</span>',
     '<span class="icon text-lg">🕐</span><span class="text-sm" data-t="navUrenregistratie">Urenregistratie</span>'),
    ('<span class="icon text-lg">💰</span><span class="text-sm">Financieel</span>',
     '<span class="icon text-lg">💰</span><span class="text-sm" data-t="navFinancieel">Financieel</span>'),
    ('<span class="icon text-lg">📅</span><span class="text-sm">Agenda</span>',
     '<span class="icon text-lg">📅</span><span class="text-sm" data-t="navAgenda">Agenda</span>'),
    ('<span class="icon text-lg">✅</span><span class="text-sm">Taken</span>',
     '<span class="icon text-lg">✅</span><span class="text-sm" data-t="navTaken">Taken</span>'),
    ('<span class="icon text-lg">📣</span><span class="text-sm">Marketing</span>',
     '<span class="icon text-lg">📣</span><span class="text-sm" data-t="navMarketing">Marketing</span>'),
    ('<span class="icon text-lg">🤝</span><span class="text-sm">Friendchise Pitch</span>',
     '<span class="icon text-lg">🤝</span><span class="text-sm" data-t="navFriendchise">Friendchise Pitch</span>'),
    ('<span class="icon text-lg">📈</span><span class="text-sm">Pipeline</span>',
     '<span class="icon text-lg">📈</span><span class="text-sm" data-t="navPipeline">Pipeline</span>'),
    ('<span class="icon text-lg">📄</span><span class="text-sm">Businessplan</span>',
     '<span class="icon text-lg">📄</span><span class="text-sm" data-t="navBusinessplan">Businessplan</span>'),
    # Dividers
    ('<div class="nav-divider mt-3">Franchise</div>',
     '<div class="nav-divider mt-3" data-t="divFranchise">Franchise</div>'),
    ('<div class="nav-divider mt-3">Organisatie</div>',
     '<div class="nav-divider mt-3" data-t="divOrganisatie">Organisatie</div>'),
    ('<div class="nav-divider mt-3">Planning</div>',
     '<div class="nav-divider mt-3" data-t="divPlanning">Planning</div>'),
    ('<div class="nav-divider mt-3">Sales & Marketing</div>',
     '<div class="nav-divider mt-3" data-t="divSalesMarketing">Sales & Marketing</div>'),
    ('<div class="nav-divider mt-3">Strategie</div>',
     '<div class="nav-divider mt-3" data-t="divStrategie">Strategie</div>'),
]

sidebar_count = 0
for old, new in sidebar_replacements:
    if old in s:
        s = s.replace(old, new, 1)
        sidebar_count += 1
print(f'✓ Sidebar labels gepatched: {sidebar_count}/{len(sidebar_replacements)}')

# ══════════════════════════════════════════════════════════════
# 3. VERVANG updateStaticLabels() MET GENERIEKE data-t LOOP
# ══════════════════════════════════════════════════════════════

old_fn = """function updateStaticLabels() {
  // Update static page titles and labels that are in HTML, not rendered by JS
  const updates = {
    'producten-titel': t('productcatalogus'),
    'producten-sub': t('naoProductlijn'),
    'producten-nieuw-btn': t('nieuwProduct'),
    'product-filter-alle': t('alleCategorien'),
  };
  Object.entries(updates).forEach(function(entry) {
    var el = document.getElementById(entry[0]);
    if (el) el.textContent = entry[1];
  });
  // Update placeholders
  var productZoek = document.getElementById('product-zoek');
  if (productZoek) productZoek.placeholder = t('zoekProduct');
}"""

new_fn = """function updateStaticLabels() {
  // Update static page titles and labels that are in HTML, not rendered by JS
  const updates = {
    'producten-titel': t('productcatalogus'),
    'producten-sub': t('naoProductlijn'),
    'producten-nieuw-btn': t('nieuwProduct'),
    'product-filter-alle': t('alleCategorien'),
  };
  Object.entries(updates).forEach(function(entry) {
    var el = document.getElementById(entry[0]);
    if (el) el.textContent = entry[1];
  });
  // Update placeholders
  var productZoek = document.getElementById('product-zoek');
  if (productZoek) productZoek.placeholder = t('zoekProduct');
  // Generieke data-t attribuut handler voor elk element met data-t=\\"key\\"
  document.querySelectorAll('[data-t]').forEach(function(el) {
    var key = el.getAttribute('data-t');
    if (key) {
      var val = t(key);
      if (val && val !== key) el.textContent = val;
    }
  });
  // data-t-placeholder voor input placeholders
  document.querySelectorAll('[data-t-placeholder]').forEach(function(el) {
    var key = el.getAttribute('data-t-placeholder');
    if (key) {
      var val = t(key);
      if (val && val !== key) el.placeholder = val;
    }
  });
}"""

if old_fn in s:
    s = s.replace(old_fn, new_fn)
    print('✓ updateStaticLabels() uitgebreid met data-t handler')
else:
    print('! updateStaticLabels() anker niet gevonden')

# Save
if s != orig:
    open(p, 'w', encoding='utf-8').write(s)
    print(f'\\n✓ index.html opgeslagen ({len(orig)} → {len(s)} bytes, +{len(s)-len(orig)})')
else:
    print('\\n! Geen wijzigingen toegepast')
