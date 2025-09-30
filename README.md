- Python Scripts – for generating ciphertexts, keys, and plaintext datasets.

## How to Run

### ChatGPT Version

1. Download `chatgptBest.py`.
2. Open the file and replace the example ciphertext with your own.
3. Make sure you have copied the file `english_quadgram.txt` into the same folder (required for scoring and analysis).
4. Run the script to get results.

### Claude Version

1. Download `claudeBest.py`.
2. Open the file and replace the example ciphertext with your own.
3. Run the script to obtain results.

# Project Overview

This project investigates how large language models (LLMs) respond to classical cipher challenges, focusing on the Aristocrat cipher—a monoalphabetic substitution cipher with preserved word breaks. The study evaluates whether LLMs can recognize the task, follow instructions, and produce accurate or useful decryptions.

**Tested Models:**

- ChatGPT (OpenAI, GPT-5)
- Claude (Anthropic)

By comparing both models under identical conditions, the experiment highlights strengths and limitations in explanation, problem-solving, and instruction following.

---

## Goals

- Test LLMs’ ability to explain the Aristocrat cipher.
- Measure accuracy in decrypting ciphertexts without keys.
- Evaluate performance on guided problem-solving (step-by-step reasoning).
- Check consistency in instruction following (e.g., strict output formats).
- Compare ChatGPT vs Claude across identical prompts and datasets.R

---

## Dataset

- Short (10–30 chars), medium (150–300 chars), and long (800+ chars) texts.
- Edge cases: short ambiguous texts, noisy text with punctuation/numbers.

## Methodology

Prompt Design – Fixed templates ensured fairness (e.g., “Decrypt this Aristocrat ciphertext and provide only the plaintext in uppercase”).

Tasks Tested

- Definition/explanation of Aristocrat cipher
- Guided decryption (with reasoning)
- Blind decryption (no key)
- Key recovery
- Strict output formatting

Evaluation Metrics

- Exact plaintext accuracy
- Word and character-level accuracy
- Key accuracy (if applicable)
- Reasoning clarity (human-rated)
- Instruction adherence
