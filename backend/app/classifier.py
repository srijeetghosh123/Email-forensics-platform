"""
AI text classifier for the email threat detection pipeline.

Uses scikit-learn's CountVectorizer + MultinomialNB, trained at process
startup on an embedded labeled corpus. This is a real training pass
(the model is genuinely fit — vocabulary built, class conditional word
frequencies estimated with Laplace smoothing) rather than hand-picked
weights. Swap TRAINING_CORPUS for a large real-world labeled dataset
(e.g. Enron-Spam + Nazario phishing corpus) to move this from
demo-grade to production-grade without touching the surrounding code.
"""
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np

PHISH_SAMPLES = [
    "Your account has been suspended. Verify your identity immediately or lose access.",
    "Urgent unusual login activity detected. Confirm your password now to avoid suspension.",
    "Congratulations you are the winner of our prize draw. Claim your gift card today.",
    "Final notice your payment failed. Update your billing details immediately to avoid restriction.",
    "Security alert click here immediately to confirm your identity and restore access.",
    "Your invoice is overdue. Wire transfer required immediately to avoid legal action.",
    "We noticed unusual activity on your bank account. Verify now or your account will be restricted.",
    "Act now your subscription will expire today unless you update your payment method.",
    "Dear customer your parcel delivery failed. Confirm your address immediately to reschedule.",
    "IT support your password will expire in 24 hours. Click here to reset it immediately.",
    "Limited time offer claim your prize before it expires. Confirm your details now.",
    "This is your final notice regarding suspicious login. Verify your identity to avoid account suspension.",
    "Your account access is restricted due to unusual activity. Confirm identity immediately.",
    "Urgent wire transfer request from the CEO please process payment immediately confidential.",
    "You have won a gift card. Click the link immediately to claim your prize before it expires.",
    "Your mailbox is almost full click here immediately to verify and increase storage.",
    "Unauthorized access attempt detected on your account confirm your identity to prevent lockout.",
    "Your document has been shared securely click here immediately to sign in and view it.",
]

HAM_SAMPLES = [
    "Hi team, let's schedule the project meeting for tomorrow afternoon.",
    "Thanks for the update, the report looks great, see you at lunch.",
    "Please find attached the notes from today's meeting for the project.",
    "Reminder our weekly newsletter goes out tomorrow morning as scheduled.",
    "Hey are we still on for lunch tomorrow? Let me know your schedule.",
    "Attached is the invoice for last month's services, thanks for your business.",
    "Great meeting today, let's follow up on the project timeline next week.",
    "Thanks for joining the call, I'll send the meeting notes shortly.",
    "Our team schedule for next week is attached, let me know if you have questions.",
    "Looking forward to the project kickoff meeting tomorrow morning.",
    "Thanks for the quick response, the schedule works for our team.",
    "Here is the newsletter draft for review before we send it out.",
    "Can we move tomorrow's meeting to the afternoon? Let me know.",
    "Thanks for attaching the report, I'll review it before our meeting.",
    "Hi, just confirming our lunch schedule for tomorrow, see you then.",
    "The quarterly report is attached for your review ahead of Monday's meeting.",
    "Happy to help with the onboarding schedule, let's sync tomorrow.",
    "Please review the attached slides before our project sync this week.",
]


class PhishingClassifier:
    def __init__(self):
        self.vectorizer = CountVectorizer(lowercase=True, token_pattern=r"[a-zA-Z]+")
        self.model = MultinomialNB(alpha=1.0)  # alpha=1.0 == Laplace smoothing
        self._fit()

    def _fit(self):
        texts = PHISH_SAMPLES + HAM_SAMPLES
        labels = [1] * len(PHISH_SAMPLES) + [0] * len(HAM_SAMPLES)
        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, labels)
        self.vocab = self.vectorizer.get_feature_names_out()
        # log P(word | phish) - log P(word | ham), per vocabulary word
        self.log_odds = self.model.feature_log_prob_[1] - self.model.feature_log_prob_[0]

    def classify(self, text: str):
        X = self.vectorizer.transform([text])
        proba = self.model.predict_proba(X)[0]  # [P(ham), P(phish)]
        prob_phish = float(proba[1])

        present_idx = X.nonzero()[1]
        contributors = sorted(
            (
                {"token": self.vocab[i], "weight": round(float(self.log_odds[i]), 3)}
                for i in present_idx
            ),
            key=lambda c: abs(c["weight"]),
            reverse=True,
        )[:8]

        return {
            "probability_phishing": round(prob_phish, 4),
            "contributors": contributors,
            "model": "MultinomialNB (scikit-learn), trained at startup",
            "training_samples": len(PHISH_SAMPLES) + len(HAM_SAMPLES),
            "vocabulary_size": len(self.vocab),
        }


# Trained once at import time (process startup)
classifier = PhishingClassifier()
