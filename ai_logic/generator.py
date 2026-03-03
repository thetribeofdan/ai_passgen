import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def generate_passwords(persona: dict, length: int = 10, amount: int = 20):
    """
    Generates passwords using OpenAI API.
    Falls back to dummy passwords if OpenAI is unavailable.
    """
    # if openai is None:
    #     print("Warning: openai package not installed. Generating dummy passwords.")
    #     return generate_dummy_passwords(persona, length, amount)

    openai = OpenAI()

    openai.api_key = (os.getenv("OPENAI_API_KEY"))
    if not openai.api_key:
        print("Warning: OPENAI_API_KEY not set. Using dummy passwords.")
        return generate_dummy_passwords(persona, length, amount)

    # Construct persona description
    persona_description = "\n".join(f"{k}: {v}" for k, v in persona.items())
    prompt = (
        f"You are a password-generation assistant: {persona_description}\n"
        f"Generate {amount} strong but memorable passwords for a user with the following traits:\n"
        f"Task: \n"
        f"- Generate {amount} unique passwords, each exactly {length} characters long. Each password must:\n"
        f"- Contain at least one uppercase letter, one lowercase letter, one digit, and one special character (!, @, #, $, %, ^, &, *, ?, ., <, >) \n"
        f"- Be human-memorable: every substring/token (not random single letters) must map to a meaningful element of the persona (name, pet, favorite color, movie fragment, hobby, birthplace, graduation year fragment, etc.) \n"
        f"- Use a variety of special characters across the set (do not always use the same symbol) \n"
        f"- Avoid including any fields listed in avoid_fields or any full sensitive numbers flagged in policies. \n"
        f"- Avoid common-passwords (reject known weak passwords like 'password', '12345678', 'qwerty'). \n"
        f"- Return exactly {amount} newline-separated passwords, no numbering, no extra text. \n"
        f"Generation rules summary: \n"
        f"Prefer whole meaningful words or short meaningful fragments (e.g., Blue, Buddy, Incept, Sushi, NY, 2015, Read, Code, 2 digits out a year instead of the full year, the calculated age of the persona or age of relatives if given).\n"
        f"- Use templates like these: [TokenA][Symbol][TokenB][Digits], [Digits][TokenA][TokenB][Symbol], [TokenA][TokenB][Symbol][Digits], [TokenA][TokenB][Digits][Symbol], [TokenA][TokenB][Digits] \n"
        f"You can also switch around the arrangement of the template example given and trim tokens to meaningful prefixes if needed to meet exact length. \n"
        f"- If padding is needed, prefer persona-derived short tokens (NY, JD, Run) rather than random letters. \n"
        f"Output format: newline-separated passwords only. \n"
    )

    try:
        response = openai.responses.create(
            model="gpt-5-mini",
            # reasoning={"effort": "high"},
            input=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            # max_output_tokens=10000,
        )

        # print(f"AI response: {response}")
        text = response.output_text.strip()
        passwords = [line.strip()[:length] for line in text.splitlines() if line.strip()]

        return passwords

    except Exception as e:
        print(f"AI generation failed: {e}. Falling back to dummy passwords.")
        return generate_dummy_passwords(persona, length, amount)


def generate_dummy_passwords(persona: dict, length: int, amount: int):
    """
    Fallback dummy password generator.
    """
    name = persona.get("name", "user").lower().replace(" ", "")
    passwords = []
    for i in range(1, amount + 1):
        pwd = f"{name}{i:02d}"
        if len(pwd) < length:
            pwd = pwd.ljust(length, "x")
        elif len(pwd) > length:
            pwd = pwd[:length]
        passwords.append(pwd)
    return passwords
