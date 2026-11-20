# 003 · Phishing URL Classifier

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** AI/ML · **Language:** Python 3.11+ (standard library only)

A tiny, **explainable** machine-learning model that scores a URL for phishing likelihood and tells you *why*. It's a logistic regression written from scratch (no NumPy, no scikit-learn) on top of 11 lexical features. It never opens the link, it only reads the string, so it is safe to run on untrusted URLs from e-mail, chat or logs.

## Why it matters

Most phishing still starts with a link. Big ML models and reputation feeds are great, but you often want a quick, offline, auditable first filter: something you can read end-to-end, that runs in milliseconds and that explains its decision to the analyst instead of returning a black-box number.

## How it works

1. **Parse** the URL with `urllib.parse.urlsplit` (no network access).
2. **Extract 11 features**, each scaled to `[0, 1]`:

   | Feature | Meaning | Learned weight |
   |---|---|---|
   | `sensitive_words` | login / verify / secure / account / wallet … (count / 3) | +3.56 |
   | `suspicious_tld` | `.xyz .top .tk .zip .click .gq .ml .cf .work .rest` | +3.46 |
   | `host_hyphens` | hyphens in host (count / 4) | +2.87 |
   | `no_https` | scheme is not `https` | +2.84 |
   | `host_digit_ratio` | share of digits in host (× 4) | +2.36 |
   | `host_is_ip` | raw IPv4 address instead of a domain | +1.82 |
   | `punycode` | `xn--` look-alike domain | +1.78 |
   | `has_at_symbol` | `user@host` trick in the authority | +0.50 |
   | `url_length` | length / 100 | +0.45 |
   | `subdomain_depth` | extra subdomain levels | +0.30 |
   | `host_entropy` | Shannon entropy of host / 4.5 | −0.21 |

   Bias: **−4.87**.
3. **Train** logistic regression with full-batch gradient descent (zero init, 3000 epochs, L2 = 0.001) on a built-in corpus of **40 fictional URLs** (20 legitimate, 20 phishing). Training is fully deterministic.
4. **Score**: `p = sigmoid(bias + Σ wᵢ·xᵢ)`; `p ≥ 0.5` → `PHISHING`.
5. **Explain**: list the top 3 features by contribution `wᵢ·xᵢ`. Exit code `1` if any URL is flagged.

## How to run

```bash
cd projects/003-phishing-url-classifier
python url_classifier.py "https://github.com/sarckan" "http://secure-login-acmebank.xyz/verify"
python url_classifier.py --eval            # 5-fold cross-validation
python url_classifier.py --json "http://198.51.100.1/login"
python -m pytest -q
```

## Example output

```text
$ python url_classifier.py "https://github.com/sarckan" "http://secure-login-acmebank.xyz/verify"
[      ok] 0.007  https://github.com/sarckan
           + url_length (+0.12)
[PHISHING] 0.998  http://secure-login-acmebank.xyz/verify
           + sensitive_words (+3.56)
           + suspicious_tld (+3.46)
           + no_https (+2.84)

$ python url_classifier.py --eval
5-fold CV accuracy on 40 URLs: 100.0%
```

## Limitations & ideas

- The training set is tiny and synthetic, so the 100 % CV score says the features separate *this* corpus, not that the model is production-ready. Retrain on a real labelled feed (e.g. your own mail-gateway verdicts) before relying on it.
- Purely lexical: a clean-looking URL on a compromised legitimate site will pass. Combine with domain age, certificate and reputation signals.
- The TLD and keyword lists are English-centric and will need tuning.
- Ideas: load/save weights as JSON, add character n-gram features, calibrate the threshold on a validation set, add a brand-similarity (edit distance) feature.
