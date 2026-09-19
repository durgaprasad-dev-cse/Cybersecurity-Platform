import json
import os
import re

from dotenv import load_dotenv
from openai import OpenAI


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-5.6-luna"
)


# =========================================================
# SUPPORTED SCAM CATEGORIES
# =========================================================

SCAM_CATEGORIES = [
    "UPI / Payment Scam",
    "Bank / KYC Scam",
    "Job Scam",
    "Investment Scam",
    "Courier Scam",
    "OTP Scam",
    "WhatsApp / Social Media Scam",
    "Government Impersonation",
    "Loan App Scam",
    "QR Code Scam",
    "Money Already Lost",
    "Other / Unclear",
]


# =========================================================
# AI SYSTEM INSTRUCTIONS
# =========================================================

SYSTEM_PROMPT = """
You are a public-facing Cyber Scam Safety Assistant.

Your job is to analyze a user's description of a suspected
online scam and provide practical, safe and understandable
cybersecurity guidance.

SAFETY RULES:

1. Never ask for or request:
   - passwords
   - OTPs
   - UPI PINs
   - ATM PINs
   - CVVs
   - full card numbers
   - banking login credentials
   - recovery codes
   - private keys

2. Never tell the user to transfer money to recover money.

3. Never claim that something is definitely a scam unless the
   evidence supplied by the user actually establishes that.
   Clearly distinguish indicators from proof.

4. Do not invent:
   - phone numbers
   - URLs
   - government procedures
   - laws
   - reporting contacts
   - bank contacts

5. Tell users to independently verify claims through the
   relevant organization's official website, application,
   branch or official contact channel.

6. If the user says money was lost or sensitive credentials
   were exposed, prioritize immediate containment and
   contacting the relevant financial institution or service
   provider through an official channel.

7. Keep the language calm and understandable for ordinary
   non-technical users.

8. Do not impersonate police, banks, government departments,
   cybersecurity authorities or financial institutions.

9. This is educational AI-assisted guidance and is not a
   substitute for an official investigation.

10. Do not repeat sensitive information that the user may
    accidentally provide.

11. Do not request sensitive information in order to perform
    the analysis.

12. If the user accidentally provides sensitive information,
    do not reproduce that information in the response.

13. Focus on practical next steps, prevention and safe
    verification.


OUTPUT FORMATTING RULES:

14. Return ONLY the requested structured JSON object.

15. Do NOT use Markdown.

16. Do NOT use Markdown headings such as:
    ### Warning Indicators
    ### What To Do Now

17. Do NOT add bullet characters such as:
    -
    *
    •
    –
    —

18. Do NOT add numbered-list prefixes such as:
    1.
    2.
    3.

19. Each item in an array must contain ONLY the actual
    statement, warning or instruction as plain text.

20. The application automatically creates headings,
    bullets and numbered lists.

21. Do NOT use HTML.

22. Do NOT use code blocks.

23. Do NOT add introductory text before the JSON response.

24. Do NOT add explanatory text after the JSON response.

25. Do NOT use emojis inside the returned fields.

26. Do not put multiple recommendations into one array item
    when they can reasonably be separated into individual
    steps.

27. Keep each array item concise and actionable.


STRUCTURE REQUIREMENTS:

scam_category:
Return exactly one supported scam category.

risk_level:
Return exactly one of:
LOW
MEDIUM
HIGH
CRITICAL
UNCERTAIN

confidence:
Return exactly one of:
LOW
MEDIUM
HIGH

summary:
Return one concise paragraph explaining the assessment.

indicators:
Return 3 to 6 separate warning indicators.
Each indicator must be one plain-text statement.

information_at_risk:
Return 1 to 5 separate types of information or accounts
that may be at risk.
Each item must be plain text.

do_now:
Return 3 to 7 separate immediate actions.
Each item must be one actionable step.

do_not:
Return 3 to 7 separate things the user should avoid.
Each item must be one actionable warning.

if_money_lost:
Return 2 to 5 separate actions relevant if money was lost.
If money loss is not indicated, explain the appropriate
next step without inventing an incident.

verification_advice:
Return 2 to 5 separate ways to independently verify the
situation.
"""


# =========================================================
# STRUCTURED AI RESPONSE SCHEMA
# =========================================================

SCHEMA = {
    "type": "object",

    "properties": {

        "scam_category": {
            "type": "string",
            "enum": SCAM_CATEGORIES
        },

        "risk_level": {
            "type": "string",
            "enum": [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
                "UNCERTAIN"
            ]
        },

        "confidence": {
            "type": "string",
            "enum": [
                "LOW",
                "MEDIUM",
                "HIGH"
            ]
        },

        "summary": {
            "type": "string"
        },

        "indicators": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "maxItems": 8
        },

        "information_at_risk": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "maxItems": 8
        },

        "do_now": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1,
            "maxItems": 8
        },

        "do_not": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1,
            "maxItems": 8
        },

        "if_money_lost": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "maxItems": 8
        },

        "verification_advice": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1,
            "maxItems": 6
        }
    },

    "required": [
        "scam_category",
        "risk_level",
        "confidence",
        "summary",
        "indicators",
        "information_at_risk",
        "do_now",
        "do_not",
        "if_money_lost",
        "verification_advice"
    ],

    "additionalProperties": False
}


# =========================================================
# CLEAN INDIVIDUAL LIST ITEMS
# =========================================================

def clean_list_item(text):
    """
    Remove accidental Markdown/list formatting
    from individual AI-generated list items.
    """

    if not isinstance(text, str):
        return str(text)

    text = text.strip()

    # -----------------------------------------------------
    # Remove Markdown heading markers
    # -----------------------------------------------------

    while text.startswith("#"):
        text = text[1:].strip()

    # -----------------------------------------------------
    # Remove common bullet markers
    # -----------------------------------------------------

    bullet_prefixes = [
        "- ",
        "* ",
        "• ",
        "– ",
        "— "
    ]

    for prefix in bullet_prefixes:

        if text.startswith(prefix):
            text = text[len(prefix):].strip()
            break

    # -----------------------------------------------------
    # Remove numbered-list prefixes
    #
    # Examples:
    # 1. Do this
    # 2) Do this
    # 10. Do this
    # -----------------------------------------------------

    text = re.sub(
        r"^\d+[\.\)]\s*",
        "",
        text
    )

    return text.strip()


# =========================================================
# CLEAN COMPLETE SCAM RESULT
# =========================================================

def clean_scam_result(result):
    """
    Normalize and clean the structured AI response
    before sending it to the Flask frontend.
    """

    # -----------------------------------------------------
    # Fields that must contain clean lists
    # -----------------------------------------------------

    list_fields = [
        "indicators",
        "information_at_risk",
        "do_now",
        "do_not",
        "if_money_lost",
        "verification_advice"
    ]

    # -----------------------------------------------------
    # Clean every list field
    # -----------------------------------------------------

    for field in list_fields:

        value = result.get(field, [])

        # If AI accidentally returns a single string,
        # convert it into a list.
        if not isinstance(value, list):
            value = [value]

        cleaned_items = []

        for item in value:

            cleaned = clean_list_item(item)

            if cleaned:
                cleaned_items.append(cleaned)

        result[field] = cleaned_items

    # -----------------------------------------------------
    # Clean normal text fields
    # -----------------------------------------------------

    text_fields = [
        "scam_category",
        "risk_level",
        "confidence",
        "summary"
    ]

    for field in text_fields:

        if field in result and isinstance(
            result[field],
            str
        ):

            result[field] = result[field].strip()

    return result


# =========================================================
# SCAM ANALYSIS FUNCTION
# =========================================================

def analyze_scam(
    user_text,
    category="Other / Unclear",
    requested_actions=None,
    user_action="I am not sure",
    current_status="I am unsure"
):

    # -----------------------------------------------------
    # Clean user input
    # -----------------------------------------------------

    user_text = (user_text or "").strip()


    # -----------------------------------------------------
    # Make sure requested_actions is always a list
    # -----------------------------------------------------

    requested_actions = requested_actions or []


    # -----------------------------------------------------
    # Validate description length
    # -----------------------------------------------------

    if len(user_text) < 10:

        raise ValueError(
            "Please describe what happened in at least 10 characters."
        )


    if len(user_text) > 6000:

        raise ValueError(
            "Please keep your description below 6000 characters."
        )


    # -----------------------------------------------------
    # Validate category
    # -----------------------------------------------------

    if category not in SCAM_CATEGORIES:

        category = "Other / Unclear"


    # -----------------------------------------------------
    # READ OPENAI API KEY FROM ENVIRONMENT
    # -----------------------------------------------------

    api_key = os.getenv(
        "OPENAI_API_KEY"
    )


    # -----------------------------------------------------
    # MAKE SURE API KEY EXISTS
    # -----------------------------------------------------

    if not api_key:

        raise RuntimeError(
            "OPENAI_API_KEY is not configured. "
            "Please check your .env file."
        )


    # -----------------------------------------------------
    # CREATE OPENAI CLIENT
    # -----------------------------------------------------

    client = OpenAI(
        api_key=api_key
    )


    # -----------------------------------------------------
    # BUILD COMPLETE USER PROMPT
    # -----------------------------------------------------

    user_prompt = f"""
USER INCIDENT ASSESSMENT

Selected incident category:
{category}


What happened:
{user_text}


Actions requested by the other person:
{requested_actions}


What the user did:
{user_action}


Current situation:
{current_status}


ANALYSIS INSTRUCTIONS

Use ALL of the information above when assessing
the situation.

Do not assume that a selected category proves
that the incident belongs to that category.

Assess the evidence provided by the user.

Identify warning indicators separately from proof.

Prioritize immediate safety actions when there is
a possibility of financial loss, account compromise,
credential exposure or device compromise.

Return only the structured response defined by
the provided JSON schema.
"""


    # -----------------------------------------------------
    # SEND REQUEST TO OPENAI
    # -----------------------------------------------------

    try:

        response = client.responses.create(

            model=MODEL,

            input=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },

                {
                    "role": "user",
                    "content": user_prompt
                }
            ],

            text={
                "format": {
                    "type": "json_schema",
                    "name": "scam_analysis",
                    "strict": True,
                    "schema": SCHEMA
                }
            }
        )

    except Exception as exc:

        raise RuntimeError(
            f"AI analysis failed: {exc}"
        )


    # -----------------------------------------------------
    # CHECK AI RESPONSE
    # -----------------------------------------------------

    if not response.output_text:

        raise RuntimeError(
            "The AI returned an empty response."
        )


    # -----------------------------------------------------
    # CONVERT JSON RESPONSE INTO PYTHON DICTIONARY
    # -----------------------------------------------------

    try:

        result = json.loads(
            response.output_text
        )

    except json.JSONDecodeError:

        raise RuntimeError(
            "The AI returned an invalid structured response."
        )


    # =====================================================
    # CLEAN AI RESULT
    # =====================================================

    result = clean_scam_result(
        result
    )


    # -----------------------------------------------------
    # RETURN FINAL STRUCTURED RESULT
    # -----------------------------------------------------

    return result