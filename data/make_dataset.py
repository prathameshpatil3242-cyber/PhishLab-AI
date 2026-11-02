"""
Generate data/sample_messages.csv  (run once from the project folder)

The dataset is 100% FICTIONAL and written for teaching purposes only.
It is far too small to prove real-world detection quality — see README.
"""

import csv
import os

PHISHING = [
    "From: security@paypa1-verify.com\nSubject: Urgent: your account will be suspended\nDear customer, verify your password within 24 hours or your account will be closed. Click here to verify now.",
    "From: alerts@amaz0n-billing.net\nSubject: Unusual sign-in detected\nWe detected unauthorized activity on your account. Confirm your identity by entering your password at the link below immediately.",
    "Congratulations! You have won a free gift card. Claim your prize now by confirming your bank account number and paying the small processing fee.",
    "From: it-helpdesk@tkiet-support.xyz\nSubject: Password expires today\nYour mailbox password expires today. Reply with your current password and one-time code to keep your account active.",
    "Dear user, your account has been locked due to suspicious login. Act now and re-verify your identity within 12 hours to avoid permanent suspension.",
    "From: no-reply@micr0soft-security.com\nSubject: Final warning\nYour subscription will be cancelled. Update your billing information and credit card number immediately to avoid legal action.",
    "URGENT: Your parcel could not be delivered. Pay the tiny customs fee using a gift card and enter your tracking details on our secure page.",
    "From: bank-alerts@sbi-secure-login.top\nSubject: Unusual transaction\nWe noticed an unusual transaction on your bank account. Confirm your OTP and PIN by replying to this message within 6 hours.",
    "Dear account holder, verify your account to prevent closure. Click the link and enter your login details: http://192.168.5.10/account/verify",
    "This is your final warning. Failure to respond will lead to legal action. Wire the outstanding amount immediately using the instructions attached.",
    "From: support@flipkart-prize.com\nSubject: You are selected!\nYou are selected for a cash prize. Do not tell anyone. Pay the refundable tax fee through gift cards to claim your reward.",
    "Hello, please open the attached invoice and enable macros to view it. This is time sensitive and must be completed today.",
    "From: accounts@appleid-secure-update.com\nSubject: Verify your Apple ID\nYour Apple ID will be disabled. Confirm your identity by updating your information and sharing your verification code with our team.",
    "Dear customer, we need to re-verify your identity. Send your social security number and date of birth so we can process your request quickly.",
    "Your mailbox is full. Sign in at hxxp://secure-login.example-verify.xyz/mail to confirm your password and restore access immediately.",
    "From: hr@recruitment-scam.info\nSubject: Job offer, high salary\nYou have been selected for a high paying job. Transfer the registration fee via western union to complete your onboarding.",
    "Attention: your refund of 8,500 is pending. Confirm your bank account number and card CVV so we can release the payment today.",
    "From: delivery@corier-parcel.net\nSubject: Delivery failed\nYour parcel is on hold. Click here to update your address and pay the processing fee within 24 hours or the parcel will be returned.",
    "Dear valued customer, unusual activity was found on your wallet. Verify your crypto wallet seed phrase immediately to secure your funds.",
    "From: secure@0ffice365-login.top\nSubject: Session expired\nYour session has expired. Re-enter your username and password on this page to continue working. Do not inform anyone about this notice.",
    "You have won the weekly lottery! Claim your cash prize before it expires. Enter your UPI id and pay the release fee to receive your money.",
    "From: billing@netfIix-renew.com\nSubject: Payment declined\nYour subscription is suspended. Update your credit card number now to avoid service interruption within 24 hours.",
    "Please confirm your identity by clicking the verification link below and entering your one-time verification code. Failure to respond will suspend your access.",
    "From: admin@account-locked.info\nSubject: Account locked\nYour account will be closed permanently. Reply with your password and date of birth to restore it immediately.",
    "Urgent action required: your invoice attachment contains a payment request. Open the attached zip file and enable content to view the details.",
    "From: security@0ffice-update.xyz\nSubject: Software update\nDownload the attached update file and install it now to keep your account secure. This is a mandatory security check.",
    "Dear user, we noticed login from a new device. Confirm your identity at our verification page within 6 hours or your access will be revoked.",
    "From: wallet@bl0ckchain-secure.com\nSubject: Suspicious transaction\nYour crypto wallet is locked. Send your recovery phrase and verification code to our support team immediately.",
    "Congratulations, you are the winner of today's jackpot. Do not share this message with anyone. Pay the small tax fee using a gift card to claim the cash prize.",
    "From: notices@tax-refund-office.com\nSubject: Tax refund pending\nYour tax refund is pending approval. Enter your bank account number and OTP on the linked page to receive your refund today.",
    "Your password reset request was received. Confirm your new password by replying directly to this email with your current password for verification.",
    "From: support@amaz0n-parcel.info\nSubject: Package held\nWe could not deliver your package. Verify your account and pay the fee using the secure link before the deadline expires.",
    "Dear account holder, unusual ATM activity was detected. Transfer your balance to the safe account provided below immediately to protect your money.",
    "From: team@company-hr-mail.com\nSubject: Salary revision\nPlease open the attached spreadsheet, enable macros and enter your login credentials to view the revised salary sheet.",
    "Your account details need updating. Failure to respond within 12 hours will lead to suspension. Click the link and enter your card details.",
    "From: verify@googIe-security.top\nSubject: Security alert\nA new sign-in was detected. Re-verify your Google account by entering your password and recovery email on our page.",
    "You are selected for a special reward. Keep this confidential and pay the processing fee through bitcoin to claim your prize before midnight.",
    "From: invoice@payment-due.net\nSubject: Overdue payment\nAn overdue invoice is attached. Pay immediately by bank transfer to avoid legal action against your company.",
    "Hello user, your KYC document is expired. Submit your Aadhaar number, date of birth and a copy of your ID on the linked portal immediately.",
    "From: helpdesk@company-it-secure.com\nSubject: Mailbox quota exceeded\nYour mailbox quota is exceeded. Confirm your identity by sending your password to the helpdesk so we can increase the quota.",
    "Your shipment is stuck at customs. Pay the customs tax with a gift card and confirm your address details within 24 hours to release it.",
    "From: alert@secure-paypal-login.top\nSubject: Limited access\nYour access is limited until you verify. Login using the link and confirm your password and security question.",
    "Attention customer, your KYC will be deactivated. Enter your PIN and OTP on the verification page to reactivate your account today.",
    "From: rewards@prize-draw.xyz\nSubject: Prize notification\nYou have won a free laptop. Do not inform anyone and pay the shipping charge through our payment link to receive it.",
    "Please review the attached contract and enable macros, then re-enter your password so the document can be signed digitally today.",
    "From: security-check@account-suspended.com\nSubject: Account suspended\nYour account has been suspended for unusual activity. Reply with your OTP and password to restore full access.",
    "Urgent: your card is blocked due to unusual ATM usage. Transfer all funds to the secure holding account given in the attachment immediately.",
    "From: notice@lottery-head-office.com\nSubject: Lottery win\nYour email address was selected in our ballot draw. Pay the processing fee by wire transfer to claim your winnings this week.",
    "Dear user, your mailbox will be closed. Confirm your password and secondary email on the linked page within 6 hours to keep it active.",
    "From: billing@0nline-bank-secure.com\nSubject: Online banking alert\nWe detected a login attempt from an unknown device. Verify your net banking user id and password immediately.",
    "Your invoice is attached as a password protected file. The password is your date of birth, please reply to confirm and open it now.",
]

LEGITIMATE = [
    "From: notices@tkiet.example.edu\nSubject: Semester timetable published\nDear student, the timetable for the next semester has been published on the college portal. Please check it and report any clash to the office.",
    "Hi Ananya, thanks for attending the workshop yesterday. The slides are attached for your reference. Let me know if you have questions.",
    "From: news@opensource.example.org\nSubject: Monthly newsletter\nThis month we shipped three new features, fixed twelve bugs and welcomed four contributors. Read the full changelog on our blog.",
    "Your order has shipped. Track your parcel using the link in your account page. Delivery is expected in three to five working days.",
    "From: hr@tkiet.example.edu\nSubject: Placement drive schedule\nThe placement drive for final year students starts on Monday at 9 AM in the seminar hall. Bring two copies of your resume.",
    "Hello team, the meeting has been moved to 4 PM. Please update your calendar. The conference room link is already in the invitation.",
    "From: support@github.example\nSubject: Your support ticket #1042 was updated\nA support agent replied to your ticket. View the response by signing in to your account through the official website.",
    "Thank you for your payment of 499. Your receipt is attached. No action is needed from your side.",
    "From: library@tkiet.example.edu\nSubject: Book return reminder\nThe book 'Computer Networks' is due for return on Friday. You can renew it once from the library portal.",
    "Hi, please find attached the assignment feedback. Overall good work; review section 3 before the next submission.",
    "Your password was changed successfully on a new device. If this was not you, reset your password from the security page of our official app.",
    "From: events@tkiet.example.edu\nSubject: Tech fest registrations open\nRegistrations for the annual tech fest are now open. Teams of up to four members can register on the student portal.",
    "Weekly progress summary: you completed four exercises and scored 80 percent. Keep practising the awareness quizzes.",
    "From: noreply@bank.example\nSubject: Monthly statement\nYour monthly account statement is ready. View it by opening our official mobile app and navigating to statements.",
    "Reminder: your library fine of 20 rupees can be paid at the counter. No online payment is required.",
    "Hi! Sharing the notes from today's lecture. Please read chapter two before the next class.",
    "From: updates@weather.example\nSubject: Rain expected tomorrow\nLight to moderate rain is expected tomorrow afternoon. Carry an umbrella if you are commuting.",
    "Your appointment with the doctor has been confirmed for Thursday at 11 AM. Please arrive ten minutes early.",
    "From: security@tkiet.example.edu\nSubject: Lab safety guidelines\nPlease follow the lab safety guidelines while using the equipment. Report any issue to the lab assistant immediately.",
    "Thanks for your feedback on the survey. We have recorded your responses and will publish the summary next week.",
    "Your subscription renews automatically on the first of next month. You can manage or cancel it any time from your account settings page.",
    "From: courier@parcel.example\nSubject: Delivery attempted\nWe attempted delivery today and will try again tomorrow between 10 AM and 2 PM.",
    "Hello! Your study group session is scheduled for Saturday at 6 PM in the reading room. See you there.",
    "From: notices@tkiet.example.edu\nSubject: Exam hall allotment\nExam hall allotments are now visible on the portal. Please verify your roll number and reach the hall thirty minutes early.",
    "We received your application. Our team will review it and get back to you within a week. No further action is needed now.",
    "Your free trial ends in three days. Upgrade from your account page if you wish to continue using the service.",
    "From: teacher@tkiet.example.edu\nSubject: Project guidelines\nPlease follow the project guidelines document shared in the class group and submit the abstract by the end of this month.",
    "Thank you for joining our community. Here are three tips to get started with your new account.",
    "Your table is reserved for 7:30 PM tonight. We look forward to welcoming you.",
    "From: feedback@tkiet.example.edu\nSubject: Course feedback form\nPlease fill in the course feedback form before the end of the week. Your responses are anonymous.",
    "Reminder: the library will close early on Saturday at 4 PM. Plan your visits accordingly.",
    "Your parcel was delivered and signed for at the reception. Thank you for shopping with us.",
    "Hi colleague, could you review my pull request when you have time? No rush, it can wait until Monday.",
    "From: notices@tkiet.example.edu\nSubject: Scholarship applications\nScholarship applications for this academic year are open. Eligible students can apply through the student portal.",
    "Your two-factor authentication backup codes have been regenerated. Store them somewhere safe.",
    "Class has been cancelled tomorrow due to maintenance work. The next session will continue as scheduled.",
    "From: accounts@library.example\nSubject: New arrivals\nTwelve new titles on ethical hacking and network security have been added to the collection.",
    "Your feedback ticket has been closed. You can reopen it from the help centre if the issue persists.",
    "Morning everyone, the stand-up has been moved to 10:15. Same meeting link as before.",
    "From: notices@tkiet.example.edu\nSubject: Fee receipt\nYour fee payment for this term has been recorded. The receipt is available in the student portal.",
    "Thanks for the order! Your invoice is attached for your records.",
    "Please find the minutes of yesterday's meeting attached. Add your comments before Friday.",
    "From: support@domain.example\nSubject: Domain renewal reminder\nYour domain expires next month. Renew it from your account dashboard to avoid interruption.",
    "Your request to download your data archive has been approved. The archive will be available for seven days.",
    "Hello! A quick note that tomorrow's webinar starts 30 minutes earlier than usual.",
    "From: lab@tkiet.example.edu\nSubject: Lab batch allotment\nLab batches for this week are announced. Check the notice board for your slot and instructor name.",
    "We have updated our privacy policy. The summary of changes is on our blog; you can review the full document any time.",
    "Your bus pass has been renewed for one month. The digital pass is now active in your account.",
]

def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(base, "data", "sample_messages.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    rows = []
    for i, text in enumerate(PHISHING, start=1):
        rows.append([f"p{i:03d}", text.replace("\n", " | "), "phishing"])
    for i, text in enumerate(LEGITIMATE, start=1):
        rows.append([f"l{i:03d}", text.replace("\n", " | "), "legitimate"])
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "text", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
