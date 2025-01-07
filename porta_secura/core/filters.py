import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import spacy
from transformers import pipeline
from porta_secura.config import settings


@dataclass
class FilterResult:
    filtered_text: str
    detected_items: List[Dict[str, any]]
    sensitivity_score: float
    modified: bool


class ContentFilter:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_lg")
        self.classifier = pipeline("text-classification", model="porta-secura/content-classifier")
        self.sensitivity_threshold = settings.DEFAULT_SENSITIVITY

    def set_sensitivity(self, sensitivity: float) -> None:
        if not 0 <= sensitivity <= 1:
            raise ValueError("Sensitivity must be between 0 and 1")
        self.sensitivity_threshold = sensitivity

    def detect_personal_info(self, text: str) -> List[Dict[str, any]]:
        doc = self.nlp(text)
        personal_info = []

        for ent in doc.ents:
            if ent.label_ in ["PERSON", "ORG", "GPE", "EMAIL", "PHONE"]:
                personal_info.append({
                    "type": ent.label_,
                    "text": ent.text,
                    "start": ent.start_char,
                    "end": ent.end_char
                })

        return personal_info

    def detect_credentials(self, text: str) -> List[Dict[str, any]]:
        patterns = {
            "password": r"password[\s]*[=:]+[\s]*[\w@$!%*#?&]{8,}",
            "api_key": r"[a-zA-Z0-9_-]{32,}",
            "token": r"[a-zA-Z0-9-._~+/]+=*"
        }

        credentials = []
        for cred_type, pattern in patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                credentials.append({
                    "type": cred_type,
                    "text": match.group(),
                    "start": match.start(),
                    "end": match.end()
                })

        return credentials

    def filter_content(self, text: str) -> FilterResult:
        detected_items = []
        modified_text = text

        # Detect personal information
        personal_info = self.detect_personal_info(text)
        detected_items.extend(personal_info)

        # Detect credentials
        credentials = self.detect_credentials(text)
        detected_items.extend(credentials)

        # Classify content sensitivity
        classification = self.classifier(text)[0]
        sensitivity_score = classification["score"]

        # Apply filtering if sensitivity threshold is exceeded
        if sensitivity_score > self.sensitivity_threshold:
            for item in detected_items:
                replacement = "[REDACTED]"
                modified_text = modified_text[:item["start"]] + replacement + modified_text[item["end"]:]

        return FilterResult(
            filtered_text=modified_text,
            detected_items=detected_items,
            sensitivity_score=sensitivity_score,
            modified=modified_text != text
        )

    def validate_output(self, response: str) -> Tuple[bool, str]:
        filter_result = self.filter_content(response)
        return not filter_result.modified, filter_result.filtered_text


class FilterManager:
    def __init__(self):
        self.content_filter = ContentFilter()
        self.custom_filters = {}

    def add_custom_filter(self, name: str, filter_function: callable):
        self.custom_filters[name] = filter_function

    def remove_custom_filter(self, name: str):
        if name in self.custom_filters:
            del self.custom_filters[name]

    def process_response(self, response: str, sensitivity: Optional[float] = None) -> str:
        if sensitivity is not None:
            self.content_filter.set_sensitivity(sensitivity)

        modified_response = response

        # Apply content filter
        filter_result = self.content_filter.filter_content(modified_response)
        modified_response = filter_result.filtered_text

        # Apply custom filters
        for filter_func in self.custom_filters.values():
            modified_response = filter_func(modified_response)

        return modified_response