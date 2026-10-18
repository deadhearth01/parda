"""Sentence templates by style family and region.

`{label}` slots become entities; `[filler]` slots become ordinary words
(cities, brands, amounts …) that are never entities. Negative templates have
no entity slots: they teach the model what is *not* personal data (brands,
places, festivals, version numbers, order ids).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SLOT = re.compile(r"\{([a-z ]+)\}|\[([a-z_]+)\]")

FILLERS = {
    "city": ["Mumbai", "Pune", "Delhi", "Bengaluru", "Chennai", "Hyderabad", "Kolkata", "Jaipur", "Lucknow",
             "Kochi", "Indore", "Surat", "Nagpur", "Bhopal", "Patna", "Guwahati", "Goa", "Mysuru", "Agra",
             "London", "Berlin", "Paris", "Toronto", "Sydney", "Singapore", "Dubai", "Tokyo", "Madrid",
             "Nairobi", "Lagos", "Seoul", "Boston", "Austin", "Lisbon", "Zurich", "Vienna", "Oslo"],
    "amount": ["499", "1,250", "2,999", "15,000", "780", "3,450", "12,600", "89,999", "240", "5,500",
               "18,750", "999", "7,200", "64,000", "1,10,000", "360", "45", "1,875", "22,300", "650"],
    "time": ["9:30 am", "10 am", "11:15", "2 pm", "3:45 pm", "4 pm", "5:30", "6 pm", "7:15 pm", "8 pm",
             "noon", "midnight", "half past nine", "quarter to six", "10:05", "13:40", "16:20", "18:00"],
    "weekday": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "tomorrow",
                "today", "tonight", "next week", "this weekend"],
    "order": ["#A1029", "#OD4471", "#77810", "#INV-2231", "#ZX-9001", "#B7754", "#R-1180", "#55321",
              "#PO-8812", "#TK-3390", "#Q-6612", "#S-7743", "#M-1209", "#K-4410", "#88231", "#D-5567"],
    "version": ["1.2.3", "2.0.1", "3.14.2", "0.9.8", "4.1.0", "10.2.4", "5.0.0-rc1", "1.18.2", "7.3.1",
                "2.4.6", "12.0.3", "0.3.17", "6.2.0", "8.1.4", "1.0.0"],
    "number": ["2", "3", "4", "5", "6", "7", "8", "10", "12", "15", "20", "25", "30", "45", "60", "90"],
    "team": ["platform", "payments", "growth", "data", "infra", "mobile", "search", "billing", "support",
             "design", "security", "finance", "sales", "marketing", "legal", "procurement"],
    "topic": ["the quarterly report", "the onboarding checklist", "the migration plan", "the sprint review",
              "the budget sheet", "the release notes", "the vendor contract", "the audit findings",
              "the product roadmap", "the hiring plan", "the incident review", "the tax filing",
              "the travel policy", "the API docs", "the pricing page", "the launch email"],
    "festival": ["Diwali", "Holi", "Eid", "Christmas", "Onam", "Pongal", "Navratri", "Durga Puja",
                 "Ganesh Chaturthi", "Baisakhi", "Bihu", "New Year"],
    "food": ["biryani", "dosa", "paneer tikka", "chole bhature", "masala chai", "pav bhaji", "idli sambar",
             "pasta", "ramen", "tacos", "falafel", "sushi", "pizza", "dal makhani", "rajma chawal"],
    "brand": [],  # filled from entities.BRANDS at import time
}


@dataclass(frozen=True)
class Template:
    text: str
    region: str
    labels: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        labels = tuple(m.group(1) for m in SLOT.finditer(self.text) if m.group(1))
        object.__setattr__(self, "labels", labels)


def _t(region: str, *texts: str) -> list[Template]:
    return [Template(t, region) for t in texts]


FAMILIES: dict[str, list[Template]] = {
    "chat_prompt": _t(
        "india",
        "Can you draft a polite reminder to {person} about the pending invoice of Rs [amount]?",
        "Write a thank you note to {person} ji for helping with [topic] last [weekday].",
        "Summarise this complaint from {person}, who lives at {address}.",
        "Translate this into Hindi for {person}: the cheque from {organization} will reach by [weekday].",
        "My PAN is {pan number} and Aadhaar is {aadhaar number}, please fill the ITR form for me.",
        "Help me reply to {email} explaining why the refund for order [order] is late.",
    ) + _t(
        "global",
        "Draft a short email to {person} confirming the meeting on [weekday] at [time].",
        "Rewrite this message for {person} at {organization} so it sounds more formal.",
        "Explain to {person} why the invoice for [topic] was sent to {email} twice.",
        "My date of birth is {date of birth}; which travel insurance plans can I pick?",
        "Create a cover letter for {person} applying to {organization} in [city].",
    ),
    "whatsapp": _t(
        "india",
        "bhai {person} ko bol dena ki kal meeting [time] baje hai",
        "{person} ji, mera number {phone number} hai, kal call karna please",
        "yaar mera UPI {upi id} hai, [amount] bhej do aaj raat tak",
        "Didi, {person} ka address {address} hai, parcel wahan bhejna hai",
        "bhai mera account number {bank account number} aur IFSC {ifsc code} hai, kal transfer karna",
        "kal {person} bhaiya se baat karna, unka mail {email} hai",
    ) + _t(
        "global",
        "hey can you ping {person} on {phone number} before [time]?",
        "lol {person} just sent the photos from [city], my email is {email} if you want them",
        "running late, tell {person} I'll be there by [time] 🙏",
        "the wifi password: {password} — don't share it with the neighbours",
        "my new insta is {username}, follow me 😄",
    ),
    "sms": _t(
        "india",
        "Dear {person}, your OTP for login is valid for [number] minutes. Do not share.",
        "Rs [amount] debited from A/c {bank account number} to UPI {upi id} on [weekday]. Not you? Call {phone number}",
        "Dear customer, your Aadhaar {aadhaar number} has been linked to PAN {pan number} successfully.",
        "Shri {person}, your gas cylinder booking [order] is confirmed. Delivery to {address}.",
        "Hi {person} ji, your appointment at [city] clinic is at [time] tomorrow. Reply Y to confirm.",
    ) + _t(
        "global",
        "Your card ending {credit card number} was charged [amount] at a store in [city].",
        "Hi {person}, your parcel [order] arrives [weekday]. Track updates sent to {email}.",
        "Login from new device at {ip address}. If this wasn't you, reset your password.",
        "Reminder: {person}, your dentist appointment is on [weekday] at [time].",
    ),
    "email": _t(
        "india",
        "Dear {person},\nPlease find attached the offer letter from {organization}. Kindly reply to {email} by [weekday].",
        "Hi {person} sir,\nThe salary for this month will be credited to A/c {bank account number}, IFSC {ifsc code}.",
        "Respected Madam,\nI, {person}, residing at {address}, request a duplicate bill for consumer no. [order].",
        "Hello {person} ji,\nAs discussed, my PAN is {pan number}. Please share the Form 16 on {email}.",
        "Team,\nPlease welcome {person} who joins {organization} on [weekday]. Reach them at {phone number}.",
    ) + _t(
        "global",
        "Dear {person},\nThank you for your application to {organization}. We will contact you at {email}.",
        "Hi {person},\nYour new account username is {username} and the temporary password: {password}",
        "Hello {person},\nPlease update the billing address to {address} before [weekday].",
        "Dear Ms. {person},\nYour passport {passport number} must be valid for six months after travel.",
        "Hi team,\n{person} from {organization} will join the call at [time]; dial-in {phone number}.",
    ),
    "support_ticket": _t(
        "india",
        "Ticket [order]: Customer {person} ({phone number}) reports that the refund to {upi id} has not arrived.",
        "Ticket [order]: KYC rejected for {person}, PAN {pan number} does not match Aadhaar {aadhaar number}.",
        "Ticket [order]: delivery to {address} failed twice, customer {person} ji asks for a call back.",
        "Ticket [order]: {person} cannot log in, registered email {email}, last login from {ip address}.",
        "Ticket [order]: chargeback on card {credit card number} raised by {person} for Rs [amount].",
    ) + _t(
        "global",
        "Case [order]: {person} ({email}) says the invoice for [topic] is wrong.",
        "Case [order]: account {username} locked after failed logins from {ip address}.",
        "Case [order]: {person} asks us to update the shipping address to {address}.",
        "Case [order]: customer {person} reports a duplicate charge on card {credit card number}.",
        "Case [order]: please call {person} back on {phone number} about [topic].",
    ),
    "kyc_form": _t(
        "india",
        "Name: {person}\nDOB: {date of birth}\nPAN: {pan number}\nAadhaar: {aadhaar number}",
        "Applicant: {person}\nMobile: {phone number}\nEmail: {email}\nAddress: {address}",
        "Account holder: {person}\nAccount no: {bank account number}\nIFSC: {ifsc code}\nUPI: {upi id}",
        "Full name: {person}\nPassport no: {passport number}\nDate of birth: {date of birth}",
        "Nominee: {person}\nRelation: spouse\nNominee DOB: {date of birth}\nContact: {phone number}",
    ) + _t(
        "global",
        "Full name: {person}\nDate of birth: {date of birth}\nPassport number: {passport number}",
        "Applicant: {person}\nEmail: {email}\nPhone: {phone number}\nAddress: {address}",
        "Account holder: {person}\nIBAN / account: {bank account number}\nEmployer: {organization}",
        "Cardholder: {person}\nCard number: {credit card number}\nBilling address: {address}",
    ),
    "resume": _t(
        "india",
        "{person} | {email} | {phone number} | [city]\nSoftware engineer with [number] years at {organization}.",
        "Curriculum vitae of {person}\nDate of birth: {date of birth}\nAddress: {address}",
        "Contact: {person}, {phone number}, {email}. Previously worked with {organization} on [topic].",
        "Name: {person}\nEducation: B.Tech, {organization}\nPassport: {passport number}",
    ) + _t(
        "global",
        "{person}\n{email} · {phone number} · [city]\nSenior analyst, {organization}",
        "Résumé — {person}, born {date of birth}, open to roles in [city].",
        "References: {person} ({organization}), reachable at {email}.",
        "Portfolio: github user {username}; contact {person} at {email}.",
    ),
    "code": _t(
        "india",
        "# TODO(ravi): remove before commit\nDB_PASSWORD = \"{password}\"  # pwd for staging",
        "const customer = { name: \"{person}\", pan: \"{pan number}\", phone: \"{phone number}\" };",
        "assert validate_aadhaar(\"{aadhaar number}\")  # test data from {person}",
        "curl -X POST /pay -d upi={upi id} -d ifsc={ifsc code}  # verified by {person}",
        "user = User(email=\"{email}\", name=\"{person}\", city=\"[city]\")",
    ) + _t(
        "global",
        "ssh {username}@{ip address} -p [number]22  # password: {password}",
        "test_user = {\"name\": \"{person}\", \"card\": \"{credit card number}\"}",
        "SMTP_USER = \"{email}\"\nSMTP_PASS = \"{password}\"",
        "# owner: {person} <{email}>\nALLOWED_IPS = [\"{ip address}\"]",
    ),
    "log": _t(
        "india",
        "[INFO] payment from {upi id} for Rs [amount] succeeded (customer {person})",
        "[WARN] KYC mismatch: pan={pan number} aadhaar={aadhaar number} user={username}",
        "[ERROR] SMS to {phone number} failed after [number] retries",
        "[INFO] login ok user={email} ip={ip address}",
        "[DEBUG] payout account={bank account number} ifsc={ifsc code}",
    ) + _t(
        "global",
        "[INFO] login ok user={username} ip={ip address}",
        "[WARN] password reset requested for {email} from {ip address}",
        "[ERROR] card {credit card number} declined for {person}",
        "[INFO] new signup {person} <{email}> from [city]",
    ),
    "invoice": _t(
        "india",
        "Invoice [order]\nBill to: {person}, {address}\nGSTIN on file, PAN {pan number}\nAmount: Rs [amount]",
        "Received with thanks from {person} the sum of Rs [amount] via UPI {upi id}.",
        "Payment to {organization}: A/c {bank account number}, IFSC {ifsc code}, ref [order].",
        "Invoice [order] for {person} ji, contact {phone number}, due by [weekday].",
    ) + _t(
        "global",
        "Invoice [order]\nBill to: {person}\n{address}\nTotal due: [amount]",
        "Remit [amount] to {organization}, account {bank account number}, reference [order].",
        "Paid by card {credit card number} — receipt sent to {email}.",
        "Statement for {person} ({email}), period ending [weekday].",
    ),
    "meeting_notes": _t(
        "india",
        "Minutes: present were {person}, {person} and {person}. Next review on [weekday].",
        "Action item: {person} ji to share [topic] with {organization} by [weekday].",
        "Notes: {person} will call the vendor on {phone number} about [topic].",
        "Attendees: {person} (Chair), {person}. Venue: {address}.",
    ) + _t(
        "global",
        "Attendees: {person}, {person}, {person} ({organization}).",
        "Action: {person} to email [topic] to {email} by [weekday].",
        "Decision: {person} owns [topic]; backup is {person}.",
        "Notes from [city]: {person} presented [topic] to {organization}.",
    ),
    "travel": _t(
        "india",
        "PNR [order]: passenger {person}, age [number], mobile {phone number}, Rajdhani to [city].",
        "Hotel booking for {person} ji at [city], check-in [weekday], ID: passport {passport number}.",
        "Cab pickup for {person} from {address} at [time].",
        "Visa application: {person}, passport {passport number}, DOB {date of birth}.",
    ) + _t(
        "global",
        "Booking confirmed for {person}, passport {passport number}, flight to [city] on [weekday].",
        "Passenger {person}, date of birth {date of birth}, seat [number]A.",
        "Hotel guest {person} ({email}) arriving [weekday] at [time].",
        "Driver will meet {person} at {address}; call {phone number} on arrival.",
    ),
    "medical": _t(
        "india",
        "Patient: {person}, DOB {date of birth}, Aadhaar {aadhaar number}, referred by Dr. {person}.",
        "Lab report for {person} ji sent to {phone number} and {email}.",
        "Admission note: {person}, address {address}, attendant {person} ({phone number}).",
        "Prescription for {person}: follow up in [number] days at [city] clinic.",
    ) + _t(
        "global",
        "Patient {person}, born {date of birth}, insurance on file with {organization}.",
        "Discharge summary for {person} sent to {email}.",
        "Next of kin: {person}, phone {phone number}, address {address}.",
        "Dr. {person} reviewed the scan for {person} on [weekday].",
    ),
    "hr": _t(
        "india",
        "Employee {person}, PAN {pan number}, salary A/c {bank account number}, IFSC {ifsc code}.",
        "Joining letter for {person}, DOB {date of birth}, reporting to {person} at {organization}.",
        "Reimburse Rs [amount] to {person} via UPI {upi id} for [topic].",
        "Smt. {person} has applied for leave from [weekday]; contact {phone number}.",
        "Background check for {person}: Aadhaar {aadhaar number}, passport {passport number}.",
    ) + _t(
        "global",
        "New hire {person} starts at {organization} on [weekday]; laptop login {username}.",
        "Payroll for {person}: account {bank account number}.",
        "Mr. {person} requested a reference letter to be sent to {email}.",
        "Emergency contact for {person}: {person}, {phone number}.",
    ),
}

NEGATIVES: dict[str, list[Template]] = {
    "chat_prompt": _t(
        "india",
        "Plan a [number] day trip to [city] with a budget of Rs [amount].",
        "Compare [brand] and [brand] for a family of four in [city].",
        "Give me a recipe for [food] that serves [number] people for [festival].",
    ) + _t(
        "global",
        "Summarise [topic] in [number] bullet points for the [team] team.",
        "What is the weather usually like in [city] in early spring?",
        "Explain the difference between [brand] and [brand] in simple terms.",
    ),
    "whatsapp": _t(
        "india",
        "yaar [festival] ki shopping kab karni hai? [brand] pe sale hai",
        "aaj [food] banega, [time] tak ghar aa jana",
        "kal [city] mein bahut baarish hai, office mat jana",
    ) + _t(
        "global",
        "anyone up for [food] [weekday] at [time]? 🍕",
        "just landed in [city], phone at [number]% battery",
        "the [brand] update broke everything again 😩",
    ),
    "sms": _t(
        "india",
        "Your order [order] for [brand] is out for delivery. Pay Rs [amount] on delivery.",
        "Recharge of Rs [amount] successful. Validity [number] days. Happy [festival]!",
        "Flat [number]% off on [brand] this [festival]. T&C apply.",
    ) + _t(
        "global",
        "Your [brand] subscription renews [weekday] for [amount].",
        "Delivery window for order [order]: [time] to [time].",
        "Storm warning for [city] [weekday]; trains may be delayed.",
    ),
    "email": _t(
        "india",
        "Hi team,\nThe [team] review for [topic] moves to [weekday] at [time] in the [city] office.",
        "Greetings,\nOur office stays closed for [festival]; [topic] resumes on [weekday].",
        "Hello all,\nPlease submit [topic] by [weekday]. The template is on the shared drive.",
    ) + _t(
        "global",
        "Hi all,\nRelease [version] of [brand] ships [weekday]; see [topic].",
        "Team,\nThe [team] offsite in [city] is confirmed for [weekday].",
        "Hello,\nAttached is [topic] for review before [time] [weekday].",
    ),
    "support_ticket": _t(
        "india",
        "Ticket [order]: app crashes on [brand] after update [version].",
        "Ticket [order]: refund policy question for [brand] purchased during [festival] sale.",
        "Ticket [order]: [number] users in [city] report slow loading after [time].",
    ) + _t(
        "global",
        "Case [order]: export to PDF fails in version [version].",
        "Case [order]: [brand] integration times out after [number] seconds.",
        "Case [order]: dark mode not saved between sessions on [brand].",
    ),
    "kyc_form": _t(
        "india",
        "Documents required: PAN card, Aadhaar card and [number] passport size photos.",
        "Form [order]: tick the box if your address is in [city]; attach a utility bill.",
        "Note: KYC must be renewed every [number] years as per the bank policy.",
    ) + _t(
        "global",
        "Section [number]: provide a recent utility bill dated within [number] months.",
        "Form [order]: signature required on page [number].",
        "Applicants from [city] must book an appointment before [weekday].",
    ),
    "resume": _t(
        "india",
        "Skills: Python, SQL, [brand], stakeholder management, [topic].",
        "Projects: built [topic] for [number] clients across [city] and [city].",
        "Languages: Hindi, English, Marathi. Hobbies: cricket, [food] cooking.",
    ) + _t(
        "global",
        "Skills: Rust, Go, Kubernetes, [brand]; led [topic].",
        "Experience: [number] years in [team]; based in [city].",
        "Certifications: AWS, Scrum, [brand] advanced.",
    ),
    "code": _t(
        "india",
        "fn main() { println!(\"version [version]\"); }  // build for [city] servers",
        "const TIMEOUT_MS = [number]000; // tuned for [brand] clients",
        "SELECT order_id FROM orders WHERE status = 'shipped' AND city = '[city]';",
    ) + _t(
        "global",
        "pip install requests==[version]  # pin for [team]",
        "for i in range([number]): retry(fetch, timeout=[number])",
        "docker run -p 8080:8080 app:[version]",
    ),
    "log": _t(
        "india",
        "[INFO] job [order] finished in [number] ms on node [city]-[number]",
        "[WARN] cache miss ratio [number]% during [festival] sale traffic",
        "[INFO] deployed version [version] to [city] region",
    ) + _t(
        "global",
        "[INFO] started worker pool size=[number] version=[version]",
        "[ERROR] upstream [brand] returned 503 after [number] retries",
        "[DEBUG] request [order] took [number] ms",
    ),
    "invoice": _t(
        "india",
        "Invoice [order]: [number] x [brand] @ Rs [amount], GST 18% extra.",
        "Quotation for [topic]: Rs [amount] valid till [weekday].",
        "Bill [order]: [food] for [number] guests, total Rs [amount].",
    ) + _t(
        "global",
        "Invoice [order]: [number] seats of [brand] at [amount] each.",
        "Credit note [order] for [amount] issued on [weekday].",
        "Estimate for [topic]: [amount], net 30.",
    ),
    "meeting_notes": _t(
        "india",
        "Agenda: [topic], [festival] bonus, office move to [city].",
        "Decision: postpone [topic] until after [festival].",
        "Next sync [weekday] [time]; owners to update [topic].",
    ) + _t(
        "global",
        "Agenda: [topic], hiring for [team], budget review.",
        "Decision: adopt [brand] for [team] from [weekday].",
        "Follow-up: share [topic] notes in the [team] channel.",
    ),
    "travel": _t(
        "india",
        "Train from [city] to [city] leaves at [time]; carry ID proof.",
        "Best time to visit [city] is after [festival], hotels are cheaper.",
        "Flight [order] to [city] delayed by [number] minutes.",
    ) + _t(
        "global",
        "Gate change for flight [order] to [city]: now boarding at [time].",
        "Day [number] itinerary: museum walk in [city], dinner at [time].",
        "Rental car pickup at [city] airport after [time].",
    ),
    "medical": _t(
        "india",
        "Take one tablet after [food] twice a day for [number] days.",
        "OPD timings in the [city] clinic: [time] to [time], closed on [festival].",
        "Drink [number] glasses of water and avoid [food] for a week.",
    ) + _t(
        "global",
        "Clinic hours on [weekday]: [time] to [time].",
        "Follow-up scan recommended in [number] weeks.",
        "Flu vaccines available at the [city] centre from [weekday].",
    ),
    "hr": _t(
        "india",
        "Holiday list: [festival], Republic Day and Independence Day are paid holidays.",
        "The [team] team is hiring [number] interns in [city].",
        "Appraisal cycle for [topic] closes on [weekday].",
    ) + _t(
        "global",
        "Open roles: [number] engineers for [team] in [city].",
        "Benefits enrolment closes [weekday] at [time].",
        "Training on [brand] for the [team] team starts [weekday].",
    ),
}


# Forms of address people type around names (never part of the person span).
FAMILIES["whatsapp"] += _t(
    "india",
    "{person} didi ko bolo kal [time] tak aa jaye, mera number {phone number} hai",
    "{person} akka, parcel aa gaya hai, OTP kisi ko mat dena",
    "{person} anna, bill {email} pe bhej do please",
    "sir {person} ne bola tha [weekday] tak payment ho jayega",
)
FAMILIES["support_ticket"] += _t(
    "india",
    "Respected {person} madam, your complaint [order] has been resolved. Call {phone number} for help.",
    "Dear {person} sir, please share your PAN {pan number} to complete the refund.",
)


def _fill_brands() -> None:
    from .entities import BRANDS

    FILLERS["brand"] = list(BRANDS)


_fill_brands()


def static_texts() -> list[str]:
    """Every fixed string templates can put into text."""
    out: list[str] = []
    for group in (FAMILIES, NEGATIVES):
        for templates in group.values():
            out += [SLOT.sub(" ", t.text) for t in templates]
    for values in FILLERS.values():
        out += values
    return out


def render(parts, region: str, style: str) -> dict:
    """Join text pieces and `(label, value)` entity pieces into a record."""
    text = ""
    entities = []
    for part in parts:
        if isinstance(part, tuple):
            label, value = part
            value = value.strip()
            entities.append({"start": len(text), "end": len(text) + len(value), "label": label})
            text += value
        else:
            text += part
    return {"text": text, "entities": entities, "region": region, "style": style}


def instantiate(template: Template, style: str, split: str, rng) -> dict:
    """Fill a template with fresh values. Retries until every entity lines up
    with token boundaries (random values occasionally glue to neighbours)."""
    from .entities import make_entity
    from .generate import aligned

    for _ in range(50):
        parts = []
        pos = 0
        for m in SLOT.finditer(template.text):
            parts.append(template.text[pos:m.start()])
            if m.group(1):
                parts.append((m.group(1), make_entity(m.group(1), rng, template.region, split)))
            else:
                parts.append(rng.choice(FILLERS[m.group(2)]))
            pos = m.end()
        parts.append(template.text[pos:])
        chars = render(parts, template.region, style)
        if aligned(chars):
            return chars
    raise AssertionError(f"could not align template: {template.text}")
