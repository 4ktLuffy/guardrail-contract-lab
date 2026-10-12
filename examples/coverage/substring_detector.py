"""A deliberately naive multilingual substring detector: the negative control for false
positives. It flags any text that contains a trigger stem in any of the languages gcl
rotates, with no sense of context -- so a security guide, a quoted attack, "ignore the blank
rows" and a Wi-Fi password note all light it up. If a real guardrail does not beat this on
`gcl coverage --hard-negatives`, its false-positive rate is no better than a word list."""
import json
import sys

STEMS = (
    "ignor", "disregard", "override", "system", "sistem", "système", "systèm", "system-prompt",
    "passw", "contrase", "mot de passe", "senha", "prompt", "secret", "segred", "segret", "geheim",
    "reveal", "revel", "verrät", "забудь", "игнор", "систем", "парол", "секрет", "раскро",
    "忽略", "无视", "系统", "密码", "秘密", "無視", "システム", "パスワード", "タネ明かし",
    "تجاهل", "النظام", "كلمة المرور", "سر ", "התעלם", "המערכת", "סיסמה", "סוד",
    "अनदेखा", "नज़रअंदाज़", "सिस्टम", "पासवर्ड", "राज़",
)

for line in sys.stdin:
    case = json.loads(line)
    text = case["text"].lower()
    print(json.dumps({"id": case["id"], "flagged": any(s in text for s in STEMS)}))
