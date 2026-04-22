"""Voeg data-t aan page headers en '+ Nieuwe X' knoppen + 'Vandaag' en directie-overzicht knoppen."""
import re
p = '/Users/lisannegarretsen/wax-affairs-crm/index.html'
s = open(p, encoding='utf-8').read()
orig = s

# H1 page headers: map statische NL label naar bestaande i18n key
h1_map = [
    ('Agenda', 'hAgenda'),
    ('Studios', 'hStudios'),
    ('Services', 'hServices'),
    ('Klanten', 'hKlanten'),
    ('Franchisees', 'hFranchisees'),
    ('Pipeline', 'hPipeline'),
    ('Studenten', 'hStudenten'),
    ('Cohorten', 'hCohorten'),
    ('Voorraad', 'hVoorraad'),
    ('Bestellingen', 'hBestellingen'),
    ('Leveranciers', 'hLeveranciers'),
    ('Team', 'hTeam'),
    ('Urenregistratie', 'hPersoneel'),
]
h1_count = 0
for nl_label, key in h1_map:
    old = f'<h1 class="text-2xl font-bold text-gray-900">{nl_label}</h1>'
    new = f'<h1 class="text-2xl font-bold text-gray-900" data-t="{key}">{nl_label}</h1>'
    if old in s:
        s = s.replace(old, new, 1)
        h1_count += 1
print(f'H1 headers gepatcht: {h1_count}/{len(h1_map)}')

# "+ Nieuwe X" knoppen — zoek ze in statische HTML
# deze matchen: <button ...>+ Nieuwe Afspraak</button> etc.
btn_map = [
    ('+ Nieuwe Afspraak', 'btnNieuweAfspraak'),
    ('+ Nieuwe Studio', 'btnNieuweStudio'),
    ('+ Nieuwe Service', 'btnNieuweService'),
    ('+ Nieuwe Franchisee', 'btnNieuweFranchisee'),
    ('+ Nieuwe Lead', 'btnNieuweLead'),
    ('+ Nieuwe Student', 'btnNieuweStudent'),
    ('+ Nieuw Cohort', 'btnNieuwCohort'),
    ('+ Nieuwe Bestelling', 'btnNieuweBestelling'),
    ('+ Nieuwe Leverancier', 'btnNieuweLeverancier'),
    ('+ Afspraak', 'btnAfspraak'),
    ('📊 Directie Overzicht', 'btnDirectieOverzicht'),
    ('💶 Omzet Details', 'btnOmzetDetails'),
    ('🏠 Kosten', 'btnKosten'),
    ('📈 Winst & Verlies', 'btnWinstVerlies'),
]
btn_count = 0
# Zoek knop-pattern: >+ Nieuwe X<  (direct na tag, vóór </button>)
for label, key in btn_map:
    # Regex: vind >LABEL< waar niet al data-t in de tag staat
    # Simpele benadering: vervang >label< met een span+data-t constructie
    pattern = re.compile(r'>' + re.escape(label) + r'<')
    # Elke match: plak eromheen een span met data-t
    matches = list(pattern.finditer(s))
    # Vervang alle voorkomen (ook al zijn er meerdere per knop door duplicate definitions)
    if matches:
        new_s = pattern.sub(f'><span data-t="{key}">{label}</span><', s)
        if new_s != s:
            s = new_s
            btn_count += 1
print(f'Knoppen gepatcht: {btn_count}/{len(btn_map)}')

# Vandaag-knop bij agenda
vandaag_old = '>Vandaag<'
if '>Vandaag<' in s and 'data-t="vandaagLabel"' not in s:
    # Vervang alleen eerste voorkomen
    idx = s.find('>Vandaag<')
    s = s[:idx] + '><span data-t="vandaagLabel">Vandaag</span><' + s[idx+len('>Vandaag<'):]
    print('Vandaag-knop gepatcht')

# Komende Afspraken (h2 of h3 headers)
komende_old = '>Komende Afspraken<'
if komende_old in s:
    n = s.count(komende_old)
    s = s.replace(komende_old, '><span data-t="hKomendeAfspraken">Komende Afspraken</span><')
    print(f'Komende Afspraken gepatcht: {n}x')

if s != orig:
    open(p, 'w', encoding='utf-8').write(s)
    print(f'\\nindex.html opgeslagen ({len(orig)} -> {len(s)})')
else:
    print('Geen wijzigingen')
