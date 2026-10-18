"""Entity value generators. Identifiers are synthetic and checksum-valid
(Aadhaar Verhoeff, cards Luhn, IBAN mod-97, GSTIN mod-36, PAN shape)."""

from __future__ import annotations

import re
import string

from . import names

LABELS = [
    "person", "email", "phone number", "address", "organization", "date of birth",
    "aadhaar number", "pan number", "upi id", "bank account number", "ifsc code",
    "passport number", "credit card number", "ip address", "username", "password",
]
INDIA_ONLY = {"aadhaar number", "pan number", "upi id", "ifsc code"}

# ---------------------------------------------------------------------------
# vocabularies (also used by templates as non-entity fillers)
# ---------------------------------------------------------------------------
def _vocab(filename: str) -> list[str]:
    """One entry per line; blank lines and `#` comments ignored."""
    lines = (names.DATA / filename).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


ORG_REAL = _vocab("organizations.txt")
BRANDS = _vocab("brands.txt")
INDIA_CITIES = [
    ("Mumbai", "Maharashtra", "4000"), ("Pune", "Maharashtra", "4110"), ("Nagpur", "Maharashtra", "4400"),
    ("Delhi", "Delhi", "1100"), ("Gurugram", "Haryana", "1220"), ("Noida", "Uttar Pradesh", "2013"),
    ("Lucknow", "Uttar Pradesh", "2260"), ("Kanpur", "Uttar Pradesh", "2080"), ("Jaipur", "Rajasthan", "3020"),
    ("Jodhpur", "Rajasthan", "3420"), ("Ahmedabad", "Gujarat", "3800"), ("Surat", "Gujarat", "3950"),
    ("Vadodara", "Gujarat", "3900"), ("Bengaluru", "Karnataka", "5600"), ("Mysuru", "Karnataka", "5700"),
    ("Hyderabad", "Telangana", "5000"), ("Warangal", "Telangana", "5060"), ("Chennai", "Tamil Nadu", "6000"),
    ("Coimbatore", "Tamil Nadu", "6410"), ("Madurai", "Tamil Nadu", "6250"), ("Kochi", "Kerala", "6820"),
    ("Thiruvananthapuram", "Kerala", "6950"), ("Kozhikode", "Kerala", "6730"), ("Kolkata", "West Bengal", "7000"),
    ("Siliguri", "West Bengal", "7340"), ("Bhubaneswar", "Odisha", "7510"), ("Cuttack", "Odisha", "7530"),
    ("Guwahati", "Assam", "7810"), ("Shillong", "Meghalaya", "7930"), ("Patna", "Bihar", "8000"),
    ("Ranchi", "Jharkhand", "8340"), ("Bhopal", "Madhya Pradesh", "4620"), ("Indore", "Madhya Pradesh", "4520"),
    ("Chandigarh", "Chandigarh", "1600"), ("Ludhiana", "Punjab", "1410"), ("Amritsar", "Punjab", "1430"),
    ("Dehradun", "Uttarakhand", "2480"), ("Visakhapatnam", "Andhra Pradesh", "5300"),
    ("Vijayawada", "Andhra Pradesh", "5200"), ("Panaji", "Goa", "4030"), ("Raipur", "Chhattisgarh", "4920"),
]
INDIA_LOCALITIES = [
    "Bandra West", "Andheri East", "Powai", "Kothrud", "Baner", "Koregaon Park", "Karol Bagh",
    "Lajpat Nagar", "Dwarka Sector 10", "Indiranagar", "Koramangala", "Whitefield", "Jayanagar",
    "Banjara Hills", "Gachibowli", "Kukatpally", "Adyar", "T. Nagar", "Velachery", "Anna Nagar",
    "Salt Lake", "Ballygunge", "New Town", "Navrangpura", "Satellite", "Vastrapur", "Civil Lines",
    "Gomti Nagar", "Hazratganj", "Malviya Nagar", "Vaishali Nagar", "Kakkanad", "Edappally",
    "Saket", "Rajouri Garden", "Sector 15", "Sector 62", "Model Town", "Kothapet", "Ashok Nagar",
]
INDIA_LANDMARKS = [
    "Hanuman Mandir", "Shiv Mandir", "City Hospital", "Railway Station", "Bus Stand", "SBI ATM",
    "Petrol Pump", "Gurudwara", "Jama Masjid", "St. Mary's Church", "Government School",
    "Post Office", "Metro Station", "Water Tank", "Big Bazaar", "Clock Tower",
]
INDIA_APARTMENTS = [
    "Sea Breeze Apartments", "Green Valley Residency", "Sunshine Towers", "Royal Palms",
    "Silver Oak Enclave", "Lake View Heights", "Shanti Kunj", "Gokul Dham Society",
    "Prestige Shantiniketan", "Lodha Palava", "DLF Phase 3", "Brigade Gateway",
    "Hiranandani Gardens", "Sobha City", "Mahaveer Residency", "Ganga Apartments",
]
INDIA_STREETS = [
    "MG Road", "Station Road", "Link Road", "Nehru Road", "Gandhi Marg", "Tilak Road",
    "Park Street", "Brigade Road", "Linking Road", "Ring Road", "Mall Road", "Church Street",
    "Hill Road", "Lake Road", "Market Road", "Temple Street",
]
GLOBAL_ADDRESS_FORMATS = [
    ("{n} {street} Avenue, {city}, {state} {zip5}, USA",
     ["Mountain View", "Austin", "Seattle", "Boston", "Denver", "Chicago", "Portland"]),
    ("{n} {street} Road, {city} {ukpc}, UK",
     ["London", "Manchester", "Leeds", "Bristol", "Edinburgh", "Cardiff"]),
    ("{n} Rue {frstreet}, {zip5} {city}, France", ["Paris", "Lyon", "Marseille", "Toulouse", "Nantes"]),
    ("{destreet} {n}, {zip5} {city}, Germany", ["Berlin", "München", "Hamburg", "Köln", "Frankfurt am Main"]),
    ("Rua {ptstreet} {n}, {city} - SP, {cep}, Brasil", ["São Paulo", "Campinas", "Santos"]),
    ("Av. {esstreet} {n}, Col. Centro, {zip5} {city}, México", ["Ciudad de México", "Guadalajara", "Monterrey"]),
    ("{jpblock} {jpward}, {city} {jpzip}, Japan", ["Tokyo", "Osaka", "Kyoto", "Yokohama"]),
    ("{n} {street} Street, {city} NSW {au4}, Australia", ["Sydney", "Newcastle"]),
    ("{n} {street} Street, {city}, ON {capc}, Canada", ["Toronto", "Ottawa"]),
    ("Plot {n}, {street} Close, {city}, Nigeria", ["Lagos", "Abuja", "Ibadan"]),
    ("Apartment {n}, {street} Tower, {city}, United Arab Emirates", ["Dubai", "Abu Dhabi"]),
]
GLOBAL_STREETS = ["Maple", "Oak", "Cedar", "Elm", "Pine", "Willow", "Harbour", "Station", "Church", "Mill",
                  "Victoria", "Kingsway", "Riverside", "Hillcrest", "Lakeshore", "Sunset"]
FR_STREETS = ["de Rivoli", "du Faubourg", "Lafayette", "de la Paix", "Saint-Honoré", "des Lilas"]
DE_STREETS = ["Hauptstraße", "Bahnhofstraße", "Schillerstraße", "Gartenweg", "Lindenallee", "Bergstraße"]
PT_STREETS = ["Augusta", "Oscar Freire", "da Consolação", "das Flores", "Haddock Lobo"]
ES_STREETS = ["Reforma", "Insurgentes", "Juárez", "Revolución", "Chapultepec"]
JP_WARDS = ["Shibuya-ku", "Minato-ku", "Chiyoda-ku", "Shinjuku-ku", "Naka-ku"]
US_STATES = ["CA", "TX", "WA", "MA", "CO", "IL", "OR"]
PUBLIC_MAIL = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "proton.me"]
INDIA_MAIL = ["gmail.com", "yahoo.co.in", "rediffmail.com", "outlook.com", "hotmail.com"]
GLOBAL_MAIL = ["gmail.com", "outlook.com", "yahoo.com", "web.de", "orange.fr", "gmx.de", "icloud.com"]
WORK_DOMAINS = ["acmecorp.in", "brightline.io", "northwind.co.uk", "contoso.com", "fabrikam.de",
                "tailspin.com.br", "globex.co.jp", "initech.com", "umbrella-labs.in", "stark.example"]
UPI_HANDLES = ["okaxis", "okicici", "oksbi", "okhdfcbank", "ybl", "ibl", "axl", "paytm", "upi"]
IFSC_BANKS = ["HDFC", "ICIC", "SBIN", "UTIB", "KKBK", "PUNB", "BARB", "CNRB", "IDIB", "YESB", "IDFB", "INDB", "FDRL"]
USER_WORDS = ["dev", "ops", "admin", "coder", "pixel", "ninja", "rider", "cloud", "byte", "nomad"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
          "October", "November", "December"]


def static_vocab() -> list[str]:
    """Every fixed string that may appear in generated text outside person
    names (names.py keeps held-out names away from all of it)."""
    out: list[str] = []
    out += ORG_REAL + BRANDS + INDIA_LOCALITIES + INDIA_LANDMARKS + INDIA_APARTMENTS + INDIA_STREETS
    out += [c for c, s, _ in INDIA_CITIES] + [s for c, s, _ in INDIA_CITIES]
    for fmt, cities in GLOBAL_ADDRESS_FORMATS:
        out += [fmt] + cities
    out += GLOBAL_STREETS + FR_STREETS + DE_STREETS + PT_STREETS + ES_STREETS + JP_WARDS + US_STATES
    out += PUBLIC_MAIL + INDIA_MAIL + GLOBAL_MAIL + WORK_DOMAINS + UPI_HANDLES + USER_WORDS + MONTHS
    return out


# ---------------------------------------------------------------------------
# checksums
# ---------------------------------------------------------------------------
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
_ASCII_DIGITS = re.compile(r"[0-9]+")


def _verhoeff_sum(digits: str, shift: int) -> int:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[(i + shift) % 8][int(ch)]]
    return c


def verhoeff_valid(digits: str) -> bool:
    return bool(_ASCII_DIGITS.fullmatch(digits)) and _verhoeff_sum(digits, 0) == 0


def verhoeff_digit(digits: str) -> str:
    return str(_INV[_verhoeff_sum(digits, 1)])


def luhn_valid(digits: str) -> bool:
    if not _ASCII_DIGITS.fullmatch(digits):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def _luhn_complete(payload: str) -> str:
    for d in "0123456789":
        if luhn_valid(payload + d):
            return payload + d
    raise AssertionError("unreachable")


_IBAN_SPECS = {  # country: BBAN layout ("n" digit, "a" upper letter, "c" alnum)
    "DE": "n" * 18, "GB": "aaaa" + "n" * 14, "FR": "n" * 10 + "c" * 11 + "nn", "ES": "n" * 20,
    "IT": "a" + "n" * 10 + "c" * 12, "NL": "aaaa" + "n" * 10, "BE": "n" * 12, "CH": "n" * 5 + "c" * 12,
    "AT": "n" * 16, "IE": "aaaa" + "n" * 14, "PT": "n" * 21, "PL": "n" * 24, "SE": "n" * 20,
    "NO": "n" * 11, "DK": "n" * 14, "FI": "n" * 14, "AE": "n" * 19, "SA": "nn" + "c" * 18,
}


def _mod97(s: str) -> int:
    rem = 0
    for ch in s:
        rem = (rem * (10 if ch.isdigit() else 100) + (int(ch) if ch.isdigit() else ord(ch) - 55)) % 97
    return rem


def iban(rng, spaced: bool | None = None) -> str:
    country = rng.choice(sorted(_IBAN_SPECS))
    pools = {"n": string.digits, "a": string.ascii_uppercase, "c": string.digits + string.ascii_uppercase}
    bban = "".join(rng.choice(pools[k]) for k in _IBAN_SPECS[country])
    check = 98 - _mod97(bban + country + "00")
    value = f"{country}{check:02d}{bban}"
    if spaced is None:
        spaced = rng.random() < 0.6
    return " ".join(value[i:i + 4] for i in range(0, len(value), 4)) if spaced else value


_GST_ALPHABET = string.digits + string.ascii_uppercase
PAN_HOLDER = "PCHFATBLJG"


def pan(rng, holder: str | None = None) -> str:
    letters = string.ascii_uppercase
    return (
        "".join(rng.choice(letters) for _ in range(3))
        + (holder or rng.choice("PPPPPCHFATBLJG"))
        + rng.choice(letters)
        + f"{rng.randint(1, 9999):04d}"
        + rng.choice(letters)
    )


def gstin(rng) -> str:
    body = f"{rng.randint(1, 37):02d}" + pan(rng) + rng.choice("123456789ABC") + "Z"
    total = 0
    for i, ch in enumerate(body):
        product = _GST_ALPHABET.index(ch) * (2 if i % 2 else 1)
        total += product // 36 + product % 36
    return body + _GST_ALPHABET[(36 - total % 36) % 36]


# ---------------------------------------------------------------------------
# value generators
# ---------------------------------------------------------------------------
def _digits(rng, n: int, first: str = "0123456789") -> str:
    return rng.choice(first) + "".join(rng.choice(string.digits) for _ in range(n - 1))


def _pin(rng, prefix: str | None = None) -> str:
    if prefix:
        return prefix + _digits(rng, 2)
    return _digits(rng, 6, "12345678")


def _local_part(rng, region: str, split: str) -> str:
    first = names.ascii_fold(rng.choice(names.name_pool(region, "first", split))) or "user"
    last = names.ascii_fold(rng.choice(names.name_pool(region, "last", split))) or "mail"
    shape = rng.randrange(7)
    if shape == 0:
        return f"{first}.{last}"
    if shape == 1:
        return f"{first}{last}"
    if shape == 2:
        return f"{first[0]}.{last}"
    if shape == 3:
        return f"{first}_{last}"
    if shape == 4:
        return f"{first}.{last}{rng.randint(1, 99)}"
    if shape == 5:
        return f"{first}{last[0]}{rng.randint(70, 99)}"
    return f"{last}.{first}"


def _email(rng, region: str, split: str) -> str:
    pool = INDIA_MAIL if region == "india" else GLOBAL_MAIL
    domain = rng.choice(pool if rng.random() < 0.7 else WORK_DOMAINS)
    return f"{_local_part(rng, region, split)}@{domain}"


def _phone(rng, region: str) -> str:
    if region == "india":
        mobile = _digits(rng, 10, "6789")
        shape = rng.randrange(8)
        if shape == 0:
            return f"+91 {mobile[:5]} {mobile[5:]}"
        if shape == 1:
            return f"+91-{mobile}"
        if shape == 2:
            return f"+91{mobile}"
        if shape == 3:
            return f"0{mobile}"
        if shape == 4:
            return mobile
        if shape == 5:
            return f"{mobile[:5]} {mobile[5:]}"
        if shape == 6:
            return f"0{rng.choice(['11', '22', '80', '40', '44', '33'])}-{_digits(rng, 4, '23456')} {_digits(rng, 4)}"
        return f"+91 {mobile[:3]} {mobile[3:6]} {mobile[6:]}"
    shape = rng.randrange(10)
    if shape == 0:
        return f"+1 ({_digits(rng, 3, '23456789')}) 555-{_digits(rng, 4)}"
    if shape == 1:
        return f"+1 {_digits(rng, 3, '23456789')}-555-{_digits(rng, 4)}"
    if shape == 2:
        return f"+44 20 {_digits(rng, 4, '78')} {_digits(rng, 4)}"
    if shape == 3:
        return f"+44 7700 {_digits(rng, 6)}"
    if shape == 4:
        return f"+49 30 {_digits(rng, 8, '123456789')}"
    if shape == 5:
        return f"+33 6 {_digits(rng, 2)} {_digits(rng, 2)} {_digits(rng, 2)} {_digits(rng, 2)}"
    if shape == 6:
        return f"+81 3-{_digits(rng, 4)}-{_digits(rng, 4)}"
    if shape == 7:
        return f"+55 11 9{_digits(rng, 4)}-{_digits(rng, 4)}"
    if shape == 8:
        return f"+971 50 {_digits(rng, 3)} {_digits(rng, 4)}"
    return f"+234 803 {_digits(rng, 3)} {_digits(rng, 4)}"


def _india_address(rng) -> str:
    city, state, prefix = rng.choice(INDIA_CITIES)
    pin = _pin(rng, prefix)
    loc = rng.choice(INDIA_LOCALITIES)
    shape = rng.randrange(7)
    if shape == 0:
        return f"Flat {rng.randint(1, 1204)}{rng.choice(['', 'A', 'B', 'C'])}, {rng.choice(INDIA_APARTMENTS)}, {loc}, {city} {pin}"
    if shape == 1:
        return (f"H.No. {rng.randint(1, 16)}-{rng.randint(1, 9)}-{rng.randint(10, 299)}, near "
                f"{rng.choice(INDIA_LANDMARKS)}, {loc}, {city}, {state} {pin}")
    if shape == 2:
        return f"{rng.randint(1, 300)}, {rng.choice(INDIA_STREETS)}, {loc}\n{city} - {pin}"
    if shape == 3:
        return f"Plot No. {rng.randint(1, 450)}, Sector {rng.randint(1, 120)}, {city}, {state} {pin}"
    if shape == 4:
        return f"{rng.randint(1, 99)}/{rng.randint(1, 20)} {rng.choice(INDIA_STREETS)}, {city} {pin}"
    if shape == 5:
        return f"Shop {rng.randint(1, 40)}, {loc}, {city}"
    return f"#{rng.randint(1, 900)}, {rng.randint(1, 30)}th Cross, {loc}, {city} - {pin}"


def _global_address(rng) -> str:
    fmt, cities = rng.choice(GLOBAL_ADDRESS_FORMATS)
    return fmt.format(
        n=rng.randint(1, 2400), street=rng.choice(GLOBAL_STREETS), city=rng.choice(cities),
        state=rng.choice(US_STATES), zip5=_digits(rng, 5, "123456789"),
        ukpc=f"{rng.choice(['SW', 'NW', 'M', 'LS', 'BS', 'EH'])}{rng.randint(1, 20)} {rng.randint(1, 9)}{rng.choice('ABDEFGHJLN')}{rng.choice('PQRSTUWXYZ')}",
        frstreet=rng.choice(FR_STREETS), destreet=rng.choice(DE_STREETS), ptstreet=rng.choice(PT_STREETS),
        cep=f"{_digits(rng, 5, '123456789')}-{_digits(rng, 3)}", esstreet=rng.choice(ES_STREETS),
        jpblock=f"{rng.randint(1, 5)}-{rng.randint(1, 30)}-{rng.randint(1, 20)}", jpward=rng.choice(JP_WARDS),
        jpzip=f"{_digits(rng, 3, '123456789')}-{_digits(rng, 4)}", au4=_digits(rng, 4, "2"),
        capc=f"M{rng.randint(1, 9)}{rng.choice('ABCEGHJ')} {rng.randint(1, 9)}{rng.choice('ABCEGHJ')}{rng.randint(1, 9)}",
    )


def _dob(rng) -> str:
    y, m, d = rng.randint(1950, 2006), rng.randint(1, 12), rng.randint(1, 28)
    month = MONTHS[m - 1]
    shape = rng.randrange(8)
    return [
        f"{d:02d}/{m:02d}/{y}", f"{d:02d}-{m:02d}-{y}", f"{y}-{m:02d}-{d:02d}", f"{d:02d}.{m:02d}.{y}",
        f"{d} {month} {y}", f"{month} {d}, {y}", f"{d} {month[:3]} {y}", f"{m}/{d}/{y}",
    ][shape]


def _aadhaar(rng) -> str:
    base = _digits(rng, 11, "23456789")
    full = base + verhoeff_digit(base)
    shape = rng.randrange(3)
    if shape == 0:
        return f"{full[:4]} {full[4:8]} {full[8:]}"
    if shape == 1:
        return f"{full[:4]}-{full[4:8]}-{full[8:]}"
    return full


def _card(rng) -> str:
    network = rng.randrange(5)
    if network == 0:
        num = _luhn_complete("4" + _digits(rng, 14))
    elif network == 1:
        num = _luhn_complete(str(rng.randint(51, 55)) + _digits(rng, 13))
    elif network == 2:
        num = _luhn_complete(rng.choice(["34", "37"]) + _digits(rng, 12))
        return f"{num[:4]} {num[4:10]} {num[10:]}" if rng.random() < 0.6 else num
    elif network == 3:
        num = _luhn_complete(rng.choice(["60", "65", "81", "82"]) + _digits(rng, 13))
    else:
        num = _luhn_complete("36" + _digits(rng, 11))
        return num
    sep = rng.choice([" ", "-", ""])
    return sep.join(num[i:i + 4] for i in range(0, len(num), 4))


def _bank_account(rng, region: str) -> str:
    if region == "global" and rng.random() < 0.6:
        return iban(rng)
    return _digits(rng, rng.randint(9, 18) if region == "india" else rng.randint(9, 12), "123456789")


def _passport(rng, region: str) -> str:
    if region == "india":
        return rng.choice("ABCDEFGHJKLMNPRSTUVWY") + _digits(rng, 7, "123456789")
    shape = rng.randrange(4)
    if shape == 0:
        return _digits(rng, 9, "123456789")
    if shape == 1:
        return "C" + "".join(rng.choice(string.digits + "FGHJKLMNPRTVWXYZ") for _ in range(8))
    if shape == 2:
        return f"{rng.randint(10, 99)}{rng.choice('ABCDEFGH')}{rng.choice('VWXYZ')}{_digits(rng, 5)}"
    return rng.choice(["TK", "TR", "MZ"]) + _digits(rng, 7)


def _ip(rng) -> str:
    if rng.random() < 0.25:
        groups = [f"{rng.randint(0, 0xFFFF):x}" for _ in range(8)]
        if rng.random() < 0.5:
            return "2001:db8:" + ":".join(groups[:2]) + "::" + groups[3]
        return ":".join(groups)
    first = rng.choice([10, 172, 192, rng.randint(11, 223)])
    if first == 172:
        return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if first == 192:
        return f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _username(rng, region: str, split: str) -> str:
    first = names.ascii_fold(rng.choice(names.name_pool(region, "first", split))) or "user"
    shape = rng.randrange(5)
    if shape == 0:
        return f"@{first}_{rng.randint(1, 999)}"
    if shape == 1:
        return f"{first}.{rng.choice(USER_WORDS)}"
    if shape == 2:
        return f"{first[:3]}{rng.randint(1980, 2010)}"
    if shape == 3:
        return f"@{rng.choice(USER_WORDS)}{first}"
    return f"{first}{rng.randint(10, 99)}"


_PW_CHARS = string.ascii_letters + string.digits + "!@#$%^&*?"


def _password(rng) -> str:
    n = rng.randint(8, 14)
    pw = [rng.choice(string.ascii_letters), rng.choice(string.digits), rng.choice("!@#$%^&*?")]
    pw += [rng.choice(_PW_CHARS) for _ in range(n - 3)]
    rng.shuffle(pw)
    return "".join(pw)


def _upi(rng, region: str, split: str) -> str:
    if rng.random() < 0.35:
        local = _digits(rng, 10, "6789")
    else:
        local = _local_part(rng, region, split).replace("_", ".")
    return f"{local}@{rng.choice(UPI_HANDLES)}"


def _ifsc(rng) -> str:
    return rng.choice(IFSC_BANKS) + "0" + "".join(rng.choice(string.digits) for _ in range(6))


def make_entity(label: str, rng, region: str, split: str) -> str:
    """One synthetic value for `label`."""
    if label == "person":
        return names.sample_name(rng, region, split)
    if label == "email":
        return _email(rng, region, split)
    if label == "phone number":
        return _phone(rng, region)
    if label == "address":
        return _india_address(rng) if region == "india" else _global_address(rng)
    if label == "organization":
        return rng.choice(ORG_REAL)
    if label == "date of birth":
        return _dob(rng)
    if label == "aadhaar number":
        return _aadhaar(rng)
    if label == "pan number":
        return pan(rng)
    if label == "upi id":
        return _upi(rng, region, split)
    if label == "bank account number":
        return _bank_account(rng, region)
    if label == "ifsc code":
        return _ifsc(rng)
    if label == "passport number":
        return _passport(rng, region)
    if label == "credit card number":
        return _card(rng)
    if label == "ip address":
        return _ip(rng)
    if label == "username":
        return _username(rng, region, split)
    if label == "password":
        return _password(rng)
    raise ValueError(f"unknown label {label!r}")
