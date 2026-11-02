"""
phishlab/awareness_data.py
--------------------------
Fictional exercises for the Phishing Awareness Training module.

ALL content is invented for classroom use:
    * no real organisation is impersonated in a harmful way,
    * no real people or addresses are used,
    * nothing is ever e-mailed — messages are only displayed locally.

Structure of one exercise
-------------------------
id            unique string
topic         short title shown in the UI
category      grouping used for filtering
message       the fictional message the student must inspect
type          'phishing' or 'legitimate'
question      the classification question (multiple choice, single answer)
options       possible answers for `question`
answer        index of the correct option
sign_question question asking which warning signs are present
sign_options  list of {text, correct} — multi-select
explanation   shown after submitting the answer
tips          safe recommendations displayed with the explanation
"""

EXERCISES = [
    {
        "id": "ex-urgent-suspend",
        "topic": "Urgent account suspension",
        "category": "Credential theft",
        "type": "phishing",
        "message": (
            "From: security@paypa1-verify.com\n"
            "Subject: Urgent: your account will be suspended\n\n"
            "Dear customer,\n\n"
            "We detected unusual activity on your account. Your account will be "
            "suspended within 24 hours unless you verify it now. Click the link "
            "below and confirm your password to avoid closure.\n\n"
            "http://192.168.10.44/verify/account\n\n"
            "Failure to respond will lead to permanent suspension.\n"
            "— Account Security Team"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Phishing — it tries to create panic and steal a password",
            "Legitimate — every security team sends deadlines",
            "Legitimate — the link starts with http so it is safe",
            "Cannot be determined because the message is short",
        ],
        "answer": 0,
        "sign_question": "Which warning signs does this message show? (select all that apply)",
        "sign_options": [
            {"text": "Urgent deadline / threat of suspension", "correct": True},
            {"text": "A request to confirm a password", "correct": True},
            {"text": "A link using a raw IP address", "correct": True},
            {"text": "Generic greeting instead of the user's name", "correct": True},
            {"text": "A correctly spelled official company domain", "correct": False},
            {"text": "A polite tone with no deadline", "correct": False},
        ],
        "explanation": (
            "Four strong signals appear together: a 24-hour threat, a password "
            "request, a raw-IP link and a generic greeting. No legitimate bank or "
            "service asks for a password inside an e-mail, and real links use their "
            "own domain rather than an IP address."
        ),
        "tips": [
            "Never enter a password after clicking an e-mail link — open the site yourself.",
            "Raw IP links in messages are almost always suspicious.",
            "Pause when a message threatens to close your account today.",
        ],
    },
    {
        "id": "ex-fake-invoice",
        "topic": "Unexpected invoice attachment",
        "category": "Malware delivery",
        "type": "phishing",
        "message": (
            "From: billing@invoicer-parcel.net\n"
            "Subject: Invoice attached — action needed today\n\n"
            "Dear customer,\n\n"
            "Please find attached the pending invoice. Open the attached zip file "
            "and enable macros to view the details. This is time sensitive and must "
            "be completed today to avoid late charges.\n\n"
            "Regards,\nBilling Department"
        ),
        "question": "What is the safest response?",
        "options": [
            "Open the attachment and enable macros to check the invoice",
            "Reply and ask them to resend the file",
            "Do not open the attachment; contact the supposed sender using a known official channel",
            "Forward the e-mail to your friends to ask their opinion",
        ],
        "answer": 2,
        "sign_question": "Which warning signs does this message show? (select all that apply)",
        "sign_options": [
            {"text": "Unexpected attachment (zip file)", "correct": True},
            {"text": "Instruction to enable macros", "correct": True},
            {"text": "Time pressure to act today", "correct": True},
            {"text": "Sender domain does not look official", "correct": True},
            {"text": "Attachment from a person you speak to daily", "correct": False},
            {"text": "A digital receipt with no action required", "correct": False},
        ],
        "explanation": (
            "Zip attachments that ask you to 'enable macros' are a classic way to "
            "run malicious code. The deadline pressures you into skipping checks, and "
            "the sender domain 'invoicer-parcel.net' has nothing to do with a real "
            "billing system. Verify with the organisation through a channel you "
            "already trust."
        ),
        "tips": [
            "Enable macros only inside trusted, work-required documents.",
            "Confirm unexpected invoices by calling the official number.",
            "Report suspicious attachments to your mail administrator.",
        ],
    },
    {
        "id": "ex-college-notice",
        "topic": "College notice e-mail",
        "category": "Legitimate messages",
        "type": "legitimate",
        "message": (
            "From: notices@tkiet.example.edu\n"
            "Subject: Semester timetable published\n\n"
            "Dear student,\n\n"
            "The timetable for the next semester has been published on the college "
            "portal. Please check it and report any clash to the office before "
            "Friday.\n\n"
            "— Examination Cell"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Phishing — it mentions an attachment",
            "Likely legitimate — it comes from the college domain and asks for no secrets",
            "Phishing — every e-mail asking you to check something is fake",
            "Legitimate — because it uses a formal subject line",
        ],
        "answer": 1,
        "sign_question": "Which statements about this message are correct? (select all that apply)",
        "sign_options": [
            {"text": "The sender domain matches the organisation", "correct": True},
            {"text": "No password, OTP or payment is requested", "correct": True},
            {"text": "There is no urgent threat or countdown", "correct": True},
            {"text": "It asks you to confirm your password today", "correct": False},
            {"text": "It uses a raw IP address link", "correct": False},
            {"text": "It demands a fee via gift card", "correct": False},
        ],
        "explanation": (
            "A legitimate message usually comes from the organisation's own domain, "
            "does not ask for secrets, and does not threaten you with an immediate "
            "deadline. Remember: 'likely legitimate' is still a judgement — the safe "
            "habit is to open the portal yourself instead of clicking a link."
        ),
        "tips": [
            "Check the sending domain carefully — it is the fastest signal.",
            "Legitimate notices rarely need passwords or payments.",
            "When unsure, open the official portal directly from a bookmark.",
        ],
    },
    {
        "id": "ex-prize-winner",
        "topic": "Prize / lottery notification",
        "category": "Scam offers",
        "type": "phishing",
        "message": (
            "From: rewards@prize-draw.xyz\n"
            "Subject: Congratulations! You have won\n\n"
            "Dear user,\n\n"
            "You are selected as today's lucky winner of a free laptop. Do not tell "
            "anyone about this message or the prize will be cancelled. Pay only the "
            "small refundable shipping charge using a gift card to claim your reward "
            "within 12 hours.\n\n"
            "Claim team"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Legitimate — prizes are always real on the internet",
            "Legitimate — because only a small fee is required",
            "Phishing — prize bait, secrecy and an unusual payment method",
            "Phishing — only because the subject has an exclamation mark",
        ],
        "answer": 2,
        "sign_question": "Which warning signs does this message show? (select all that apply)",
        "sign_options": [
            {"text": "Too-good-to-be-true prize offer", "correct": True},
            {"text": "Instruction to keep it secret", "correct": True},
            {"text": "Payment demanded through a gift card", "correct": True},
            {"text": "A short deadline to claim", "correct": True},
            {"text": "An official purchase receipt from your bank", "correct": False},
            {"text": "A normal delivery update with a tracking number", "correct": False},
        ],
        "explanation": (
            "Real prize draws never ask winners to pay 'shipping' with a gift card, "
            "and never tell you to hide the message from others. Secrecy stops you "
            "from asking a friend who would spot the scam immediately."
        ),
        "tips": [
            "If you did not enter a draw, you cannot have won it.",
            "Gift-card payments demanded by strangers always mean a scam.",
            "Discuss surprising messages with someone you trust before acting.",
        ],
    },
    {
        "id": "ex-library-reminder",
        "topic": "Library return reminder",
        "category": "Legitimate messages",
        "type": "legitimate",
        "message": (
            "From: library@tkiet.example.edu\n"
            "Subject: Book return reminder\n\n"
            "Hello,\n\n"
            "The book 'Computer Networks' is due for return on Friday. You can renew "
            "it once from the library portal. A fine of 2 rupees per day applies "
            "after the due date.\n\n"
            "Thank you,\nLibrary Section"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Likely legitimate — no links to secrets and a plausible service message",
            "Phishing — it mentions money (the fine)",
            "Phishing — because it asks you to visit a portal",
            "Legitimate — because it mentions a book title",
        ],
        "answer": 0,
        "sign_question": "Which statements about this message are correct? (select all that apply)",
        "sign_options": [
            {"text": "It comes from the institution's own domain", "correct": True},
            {"text": "It requests no password, OTP or card detail", "correct": True},
            {"text": "A small, believable fine is mentioned with no payment link", "correct": True},
            {"text": "It threatens account closure within 6 hours", "correct": False},
            {"text": "It contains a shortened link to pay the fine", "correct": False},
            {"text": "It asks you to reply with your date of birth", "correct": False},
        ],
        "explanation": (
            "Not every mention of money is a scam. The difference is that this "
            "message explains a normal library fine, does not include a payment "
            "link and does not pressure you. Judgement matters more than one "
            "single keyword."
        ),
        "tips": [
            "Judge the whole message, not one keyword like 'money'.",
            "Service messages from your own organisation are usually safe to read.",
            "Still avoid entering passwords on any link you did not type yourself.",
        ],
    },
    {
        "id": "ex-otp-request",
        "topic": "OTP requested by 'support'",
        "category": "Credential theft",
        "type": "phishing",
        "message": (
            "From: helpdesk@company-it-secure.com\n"
            "Subject: Mailbox quota exceeded\n\n"
            "Dear user,\n\n"
            "Your mailbox quota has been exceeded and will be closed today. To "
            "increase the quota, confirm your identity by replying with your current "
            "password and the one-time code sent to your phone.\n\n"
            "IT Helpdesk"
        ),
        "question": "What should you do?",
        "options": [
            "Reply quickly with the OTP because the mailbox is important",
            "Ignore the OTP request; real IT teams never ask for passwords or OTPs",
            "Reply with the password but not the OTP",
            "Forward the e-mail to the sender to confirm it is real",
        ],
        "answer": 1,
        "sign_question": "Which warning signs does this message show? (select all that apply)",
        "sign_options": [
            {"text": "Direct request for a password", "correct": True},
            {"text": "Request for a one-time code (OTP)", "correct": True},
            {"text": "Deadline pressure (mailbox closing today)", "correct": True},
            {"text": "Sender domain differs from the real company domain", "correct": True},
            {"text": "Uses your full name from the HR record", "correct": False},
            {"text": "Includes a signed policy document", "correct": False},
        ],
        "explanation": (
            "No genuine IT department ever asks for your password or an OTP — they "
            "already have the access they need. Replying hands the attacker "
            "everything required to take over your mailbox."
        ),
        "tips": [
            "Treat passwords and OTPs as private, always.",
            "Report quota/verification scam e-mails to your IT team.",
            "Change your password immediately if you ever replied.",
        ],
    },
    {
        "id": "ex-meeting-update",
        "topic": "Team meeting update",
        "category": "Legitimate messages",
        "type": "legitimate",
        "message": (
            "From: priya@tkiet.example.edu\n"
            "Subject: Meeting moved to 4 PM\n\n"
            "Hi team,\n\n"
            "Tomorrow's project meeting has been moved to 4 PM in the seminar room. "
            "Please update your calendar. The agenda is attached as a PDF for "
            "reference.\n\n"
            "Thanks,\nPriya"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Phishing — attachments are always dangerous",
            "Phishing — because the meeting time changed",
            "Likely legitimate — a known colleague, normal content, no requests for secrets",
            "Legitimate — because a PDF cannot contain malware",
        ],
        "answer": 2,
        "sign_question": "Which statements about this message are correct? (select all that apply)",
        "sign_options": [
            {"text": "Sender appears to be a known colleague", "correct": True},
            {"text": "No password, OTP or payment is requested", "correct": True},
            {"text": "Content matches an ordinary work situation", "correct": True},
            {"text": "It contains a threat to close your account", "correct": False},
            {"text": "It hides a shortened link behind innocent text", "correct": False},
            {"text": "It asks you to enable macros in the attachment", "correct": False},
        ],
        "explanation": (
            "Normal work e-mails ask nothing private and match everyday situations. "
            "PDFs can technically contain malicious content, so the right habit is "
            "still caution with unexpected files — but nothing here shows a phishing "
            "pattern."
        ),
        "tips": [
            "Watch for e-mails that ask you to 'enable content'.",
            "Unexpected files from known people are worth a quick confirmation.",
            "Phishing usually pressures you; normal messages simply inform you.",
        ],
    },
    {
        "id": "ex-refund-pending",
        "topic": "Refund pending for bank details",
        "category": "Financial fraud",
        "type": "phishing",
        "message": (
            "From: notice@refund-office-info.com\n"
            "Subject: Your refund is pending\n\n"
            "Dear account holder,\n\n"
            "Your refund of 8,500 has been approved but cannot be credited. Confirm "
            "your bank account number, card CVV and the OTP sent to your phone so "
            "the payment can be released today. Failure to respond will cancel the "
            "refund.\n\n"
            "Refund Cell"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Legitimate — banks always ask for a CVV by e-mail",
            "Phishing — it asks for complete payment secrets and uses pressure",
            "Legitimate — because the amount seems reasonable",
            "Cannot say, because refunds are sometimes real",
        ],
        "answer": 1,
        "sign_question": "Which warning signs does this message show? (select all that apply)",
        "sign_options": [
            {"text": "Request for card CVV", "correct": True},
            {"text": "Request for an OTP", "correct": True},
            {"text": "Request for bank account number", "correct": True},
            {"text": "Threat that the refund will be cancelled", "correct": True},
            {"text": "Sent from your bank's official domain", "correct": False},
            {"text": "Contains no request for personal data", "correct": False},
        ],
        "explanation": (
            "CVV, OTP and account numbers are exactly what a fraudster needs to move "
            "money. Refund flows never require you to e-mail these values, and the "
            "cancellation threat is there to stop you verifying with the bank."
        ),
        "tips": [
            "Never share CVV or OTP with anyone, ever.",
            "Check refunds in your bank's official app instead of replying.",
            "Call the bank using the number on your card if you are unsure.",
        ],
    },
    {
        "id": "ex-security-advisory",
        "topic": "Security advisory newsletter",
        "category": "Legitimate messages",
        "type": "legitimate",
        "message": (
            "From: news@opensource.example.org\n"
            "Subject: Monthly security advisory\n\n"
            "Hello subscriber,\n\n"
            "This month we fixed twelve issues, including one moderate problem in "
            "the login component. Update to version 4.2.1 from our website. The full "
            "changelog and signature are published on our blog.\n\n"
            "— Release Team"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Phishing — because it mentions the word 'login'",
            "Likely legitimate — it points you to update from the official website, not a secret link",
            "Legitimate — because it reports issue counts",
            "Phishing — newsletters are never safe",
        ],
        "answer": 1,
        "sign_question": "Which statements about this message are correct? (select all that apply)",
        "sign_options": [
            {"text": "It tells you to update from the official website rather than a hidden link", "correct": True},
            {"text": "It requests no personal credentials", "correct": True},
            {"text": "It comes from a publisher domain matching the product", "correct": True},
            {"text": "It asks you to send your password to the release team", "correct": False},
            {"text": "It demands payment within 6 hours", "correct": False},
            {"text": "It uses a raw IP address for the download", "correct": False},
        ],
        "explanation": (
            "Good security messages point you to official channels and never ask for "
            "credentials. The safe habit is to visit the project website yourself to "
            "download updates instead of clicking any link."
        ),
        "tips": [
            "Download updates only from the official site or app store.",
            "A mention of 'login' is not by itself a warning sign.",
            "Verify newsletters by visiting the publisher's site directly.",
        ],
    },
    {
        "id": "ex-kyc-expired",
        "topic": "KYC expired notice",
        "category": "Identity theft",
        "type": "phishing",
        "message": (
            "From: verify@kyc-secure-update.top\n"
            "Subject: Your KYC has expired\n\n"
            "Dear customer,\n\n"
            "Your KYC verification has expired and your account will be blocked "
            "within 6 hours. Open the link below, enter your Aadhaar number, date of "
            "birth and PIN to re-verify instantly.\n\n"
            "http://kyc-secure-update.top/verify\n\n"
            "Do not inform anyone about this notice.\n"
            "— Compliance Team"
        ),
        "question": "Is this message phishing or legitimate?",
        "options": [
            "Legitimate — KYC is an official process",
            "Legitimate — because the link uses a domain name instead of an IP",
            "Phishing — identity details, deadline, secrecy and an unofficial domain",
            "Phishing — only because it mentions Aadhaar",
        ],
        "answer": 2,
        "sign_question": "Which warning signs does this message show? (select all that apply)",
        "sign_options": [
            {"text": "Request for identity numbers (Aadhaar, date of birth)", "correct": True},
            {"text": "Request for a PIN", "correct": True},
            {"text": "Six-hour deadline to avoid blocking", "correct": True},
            {"text": "Instruction not to tell anyone", "correct": True},
            {"text": "Official government domain (gov.in)", "correct": False},
            {"text": "Instruction to visit the branch in person", "correct": False},
        ],
        "explanation": (
            "Real KYC is done in person or through a bank's official app, never by "
            "replying to an e-mail with your identity numbers and PIN. The fake "
            "urgency plus the secrecy instruction are textbook phishing tactics."
        ),
        "tips": [
            "Complete KYC only through official channels you initiate yourself.",
            "Never share PINs or identity numbers by e-mail.",
            "Check the registered domain — '.top' here is not your bank or a government site.",
        ],
    },
]


def get_exercises(category=None):
    """Return exercises, optionally filtered by category."""
    if category and category != "All":
        return [e for e in EXERCISES if e["category"] == category]
    return list(EXERCISES)


def get_exercise(exercise_id):
    """Fetch one exercise by id (returns None when unknown)."""
    for e in EXERCISES:
        if e["id"] == exercise_id:
            return e
    return None


def categories():
    """Unique category names for the filter buttons."""
    seen = []
    for e in EXERCISES:
        if e["category"] not in seen:
            seen.append(e["category"])
    return seen


def grade(exercise, selected_signs, answer_index):
    """
    Score one submission.

    Parameters
    ----------
    exercise      dict from EXERCISES
    selected_signs list[int]  indexes the student ticked in sign_options
    answer_index  int         index chosen for the classification question

    Returns (points, max_points, details) — 4 points for the classification
    question and up to 4 points for the warning-sign question.
    """
    details = {"signs": [], "answer_correct": False}
    max_points = 8

    if not isinstance(answer_index, int) or not (0 <= answer_index < len(exercise["options"])):
        raise ValueError("Please choose one of the answer options.")

    answer_correct = answer_index == exercise["answer"]
    points = 4 if answer_correct else 0
    details["answer_correct"] = answer_correct

    selected = set(selected_signs or [])
    for idx in selected:
        if not (0 <= idx < len(exercise["sign_options"])):
            raise ValueError("Invalid warning-sign selection.")

    correct_signs = [i for i, s in enumerate(exercise["sign_options"]) if s["correct"]]
    chosen_correct = [i for i in selected if i in correct_signs]
    chosen_wrong = [i for i in selected if i not in correct_signs]

    sign_points = (4.0 * len(chosen_correct) / len(correct_signs)) if correct_signs else 0
    if len(exercise["sign_options"]) - len(correct_signs):
        sign_points -= (4.0 * len(chosen_wrong) / (len(exercise["sign_options"]) - len(correct_signs)))
    sign_points = max(0.0, round(sign_points, 1))

    details["signs"] = [
        {
            "text": exercise["sign_options"][i]["text"],
            "correct_choice": i in correct_signs,
            "selected": i in selected,
        }
        for i in range(len(exercise["sign_options"]))
    ]

    return points + sign_points, max_points, details
